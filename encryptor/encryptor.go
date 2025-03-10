package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encryptor/models"
	"errors"
	"fmt"
	mrand "math/rand"
	"time"
)

// OIDs for EC keys (P-256)
var oidEcPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
var oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}

// ASN.1 structures for SPKI (public key)
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

type subjectPublicKeyInfo struct {
	Algo      algorithmIdentifier
	PublicKey asn1.BitString
}

// ASN.1 structures for EC private key (embedded in PKCS#8)
type ecPrivateKeyASN struct {
	Version    int
	PrivateKey []byte
	// Include the public key as an explicit tag 1 (optional)
	PublicKey asn1.BitString `asn1:"explicit,tag:1,optional"`
}

type pkcs8 struct {
	Version    int
	Algo       algorithmIdentifier
	PrivateKey []byte
}

// Encryptor encapsulates the crypto methods.
type Encryptor struct{}

// NewEncryptor returns a new Encryptor instance.
func NewEncryptor() *Encryptor {
	return &Encryptor{}
}

// GenerateKeys creates an ECDH key pair using P-256 and returns:
// - privateKeyString (PKCS#8, base64 encoded)
// - publicKeyString (SPKI, base64 encoded)
// - the native private key for further operations.
func (e *Encryptor) GenerateKeys() (privateKeyString string, publicKeyString string, privateKey *ecdh.PrivateKey, err error) {
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", nil, err
	}
	pub := priv.PublicKey()
	spkiDER, err := marshalSPKI(pub)
	if err != nil {
		return "", "", nil, err
	}
	pkcs8DER, err := marshalPKCS8(priv)
	if err != nil {
		return "", "", nil, err
	}
	// Encode using base64 (keyEncoding)
	publicKeyString = base64.StdEncoding.EncodeToString(spkiDER)
	privateKeyString = base64.StdEncoding.EncodeToString(pkcs8DER)
	return privateKeyString, publicKeyString, priv, nil
}

// ComputePostmanSecret computes a shared secret from the postman's PKCS#8 private key and the server's SPKI public key.
// The shared secret is digested with SHA-256 and then base64-encoded.
func (e *Encryptor) ComputePostmanSecret(postmanPrivateKeyBase64, serverPublicKeyBase64 string) (string, error) {
	postmanPrivDER, err := base64.StdEncoding.DecodeString(postmanPrivateKeyBase64)
	if err != nil {
		return "", err
	}
	serverPubDER, err := base64.StdEncoding.DecodeString(serverPublicKeyBase64)
	if err != nil {
		return "", err
	}
	postmanPriv, err := unmarshalPKCS8(postmanPrivDER)
	if err != nil {
		return "", err
	}
	serverPub, err := unmarshalSPKI(serverPubDER)
	if err != nil {
		return "", err
	}
	sharedSecret, err := postmanPriv.ECDH(serverPub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(sharedSecret)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

// ComputeSecret computes a shared secret using the client's SPKI public key and the server's native private key.
func (e *Encryptor) ComputeSecret(clientPublicKeyBase64 string, privateKey *ecdh.PrivateKey) (string, error) {
	clientPubDER, err := base64.StdEncoding.DecodeString(clientPublicKeyBase64)
	if err != nil {
		return "", err
	}
	clientPub, err := unmarshalSPKI(clientPubDER)
	if err != nil {
		return "", err
	}
	sharedSecret, err := privateKey.ECDH(clientPub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(sharedSecret)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

// GenerateRandomDigits returns a random string of digits with length maxDigits (default 6).
func (e *Encryptor) GenerateRandomDigits(maxDigits int) string {
	if maxDigits <= 0 {
		maxDigits = 6
	}
	mrand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	result := make([]byte, maxDigits)
	for i := 0; i < maxDigits; i++ {
		result[i] = digits[mrand.Intn(len(digits))]
	}
	return string(result)
}

// EncryptContent encrypts the given content using AES-256-CBC.
// The provided secret is base64-encoded (it should decode to 32 bytes).
// It returns an EncryptedBodyDTO with IV (base64) and hash (hex).
func (e *Encryptor) EncryptContent(content, secret string) (*models.EncryptedBodyDTO, error) {
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("secret key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	paddedContent := pkcs7Pad([]byte(content), aes.BlockSize)
	cipherText := make([]byte, len(paddedContent))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, paddedContent)
	return &models.EncryptedBodyDTO{
		IV:   base64.StdEncoding.EncodeToString(iv),
		Hash: hex.EncodeToString(cipherText),
	}, nil
}

// DecryptContent decrypts the given EncryptedBodyDTO using AES-256-CBC and the provided secret.
func (e *Encryptor) DecryptContent(content models.APIResponse[models.EncryptedBodyDTO], secret string) (string, error) {
	// Decode the secret key from base64
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret key: %v", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("invalid secret key length: expected 32 bytes, got %d", len(key))
	}

	// Initialize the AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Decode the IV from base64
	iv, err := base64.StdEncoding.DecodeString(content.Data.IV)
	if err != nil {
		return "", fmt.Errorf("failed to decode IV: %v", err)
	}
	if len(iv) != aes.BlockSize {
		return "", fmt.Errorf("invalid IV length: expected %d bytes, got %d", aes.BlockSize, len(iv))
	}

	// Decode the ciphertext (hash) from hex
	cipherText, err := hex.DecodeString(content.Data.Hash)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %v", err)
	}
	if len(cipherText)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of the AES block size")
	}

	// Decrypt the ciphertext using CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	plainPadded := make([]byte, len(cipherText))
	mode.CryptBlocks(plainPadded, cipherText)

	// Unpad the decrypted plaintext
	plaintext, err := pkcs7Unpad(plainPadded, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("failed to unpad the decrypted data: %v", err)
	}

	// Return the plaintext as a string
	return string(plaintext), nil
}
