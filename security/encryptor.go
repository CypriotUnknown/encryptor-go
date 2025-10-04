package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
)

// Encryptor class
type Encryptor struct {
	stringUtil stringUtility `json:"-"`
}

var (
	sharedInstance *Encryptor
	once           sync.Once

	curve = ecdh.P256()
)

// Singleton pattern
func GetInstance() *Encryptor {
	once.Do(func() {
		sharedInstance = &Encryptor{
			stringUtil: stringUtility{},
		}
	})
	return sharedInstance
}

// Generate ECDH key pair
func (e *Encryptor) GenerateKeys(platform Platform) *SecurityKeysOutput {
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	if platform == PlatformBrowser {
		return e.generateKeysForBrowser(privateKey)
	} else {
		return e.generateKeysForApp(privateKey)
	}

}

// Generate crypto key from base64 (full TS equivalent)
func (e *Encryptor) GenerateCryptoKeyFromBase64(dto *GenerateCryptoKeyFromBase64Dto) *KeyFromBase64Output {
	if dto.Platform == PlatformApp {
		return e.generateCryptoKeyFromBase64StringForAppPlatform(dto.Base64KeyString, dto.ReturnKey)
	} else {
		// Browser (JWK)
		return e.generateJWKCryptoKeyFromBase64String(dto.Base64KeyString)
	}
}

// Compute shared secret
func (e *Encryptor) ComputeSecret(dto *ComputeSecretDTO) string {
	var publicKey *ecdh.PublicKey
	var err error

	if dto.Platform == PlatformBrowser {
		var jwk JWK
		if err := json.Unmarshal([]byte(dto.ClientPublicKeyBase64), &jwk); err != nil {
			panic(err)
		}

		x, _ := base64.RawURLEncoding.DecodeString(jwk.X)
		y, _ := base64.RawURLEncoding.DecodeString(jwk.Y)

		pubKeyBytes := make([]byte, 65)
		pubKeyBytes[0] = 0x04
		copy(pubKeyBytes[1:33], x)
		copy(pubKeyBytes[33:65], y)

		publicKey, err = curve.NewPublicKey(pubKeyBytes)
		if err != nil {
			panic(err)
		}
	} else {
		output := e.generateCryptoKeyFromBase64StringForAppPlatform(dto.ClientPublicKeyBase64, "public")
		publicKey = output.PublicKey
	}

	sharedSecret, err := dto.PrivateKey.ECDH(publicKey)
	if err != nil {
		panic(err)
	}

	hash := sha256.Sum256(sharedSecret)
	return e.stringUtil.arrayBufferToString(hash[:], secretEncoding)
}

// Generate random digits
func (e *Encryptor) GenerateRandomDigits(maxDigits int) string {
	if maxDigits == 0 {
		maxDigits = 6
	}

	output := ""
	for range maxDigits {
		digit, _ := rand.Int(rand.Reader, big.NewInt(10))
		output += digit.String()
	}

	return output
}

// Encrypt content
func (e *Encryptor) EncryptContent(dto *EncryptContentDto) (*EncryptedBody, error) {
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	secretBytes, err := e.stringUtil.stringToArrayBuffer(dto.Secret, secretEncoding)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(secretBytes)
	if err != nil {
		return nil, err
	}

	contentBytes := []byte(dto.Content)
	padding := aes.BlockSize - len(contentBytes)%aes.BlockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	contentBytes = append(contentBytes, padtext...)

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(contentBytes))
	mode.CryptBlocks(encrypted, contentBytes)

	var hashEncoding string
	switch dto.Platform {
	case PlatformApp:
		hashEncoding = "base64"
	case PlatformBrowser:
		hashEncoding = clientEncoding
	default:
		panic("bad platform")
	}

	return &EncryptedBody{
		IV:   e.stringUtil.arrayBufferToString(iv, ivEncoding),
		Hash: e.stringUtil.arrayBufferToString(encrypted, hashEncoding),
	}, nil
}

// Decrypt content
func (e *Encryptor) DecryptContent(dto *DecryptContentDto) ([]byte, error) {
	secretBytes, err := e.stringUtil.stringToArrayBuffer(dto.Secret, secretEncoding)
	if err != nil {
		return nil, err
	}
	ivBytes, err := e.stringUtil.stringToArrayBuffer(dto.Content.IV, ivEncoding)
	if err != nil {
		return nil, err
	}

	var hashEncoding string
	switch dto.Platform {
	case PlatformApp:
		hashEncoding = "base64"
	case PlatformBrowser:
		hashEncoding = clientEncoding
	default:
		panic(fmt.Sprintf("bad platform: %s", dto.Platform))
	}

	encryptedBytes, err := e.stringUtil.stringToArrayBuffer(dto.Content.Hash, hashEncoding)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(secretBytes)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, ivBytes)

	decrypted := make([]byte, len(encryptedBytes))
	mode.CryptBlocks(decrypted, encryptedBytes)

	padding := int(decrypted[len(decrypted)-1])
	return decrypted[:len(decrypted)-padding], nil
}
