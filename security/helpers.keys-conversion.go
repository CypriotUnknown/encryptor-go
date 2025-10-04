package security

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func (e *Encryptor) generateJWKCryptoKeyFromBase64String(base64KeyString string) *KeyFromBase64Output {
	var jwk JWK
	if err := json.Unmarshal([]byte(base64KeyString), &jwk); err != nil {
		panic(fmt.Errorf("failed to unmarshal JWK: %w", err))
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		panic(fmt.Errorf("failed to decode X: %w", err))
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		panic(fmt.Errorf("failed to decode Y: %w", err))
	}

	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	copy(pubKeyBytes[1:33], xBytes)
	copy(pubKeyBytes[33:65], yBytes)

	publicKey, err := curve.NewPublicKey(pubKeyBytes)
	if err != nil {
		panic(fmt.Errorf("failed to create public key from JWK: %w", err))
	}

	var output KeyFromBase64Output

	if jwk.D != "" {
		// Private key present
		privBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
		if err != nil {
			panic(fmt.Errorf("failed to decode private key D: %w", err))
		}
		privateKey, err := curve.NewPrivateKey(privBytes)
		if err != nil {
			panic(fmt.Errorf("failed to create private key D: %w", err))
		}

		output = KeyFromBase64Output{
			PrivateKey: privateKey,
		}
	} else {
		output = KeyFromBase64Output{
			PublicKey: publicKey,
		}
	}

	return &output
}

// Helper for app platform
func (e *Encryptor) generateCryptoKeyFromBase64StringForAppPlatform(base64KeyString string, returnKey GeneratedKeyReturnKey) *KeyFromBase64Output {
	keyBytes, err := e.stringUtil.stringToArrayBuffer(base64KeyString, keyEncoding)
	if err != nil {
		panic(fmt.Errorf("failed to decode base64 key: %w", err))
	}

	switch returnKey {
	case Private:
		privInterface, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			panic(fmt.Errorf("failed to parse PKCS8 private key: %w", err))
		}

		ecdsaPriv, ok := privInterface.(*ecdsa.PrivateKey)
		if !ok {
			panic(fmt.Errorf("key is not an ECDSA private key"))
		}

		privKey, err := curve.NewPrivateKey(ecdsaPriv.D.Bytes())
		if err != nil {
			panic(fmt.Errorf("failed to extract key from base64"))
		}
		return &KeyFromBase64Output{
			PrivateKey: privKey,
		}

	case Public:
		pubInterface, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			panic(fmt.Errorf("failed to parse SPKI public key: %w", err))
		}

		ecdsaPub, ok := pubInterface.(*ecdsa.PublicKey)
		if !ok {
			panic(fmt.Errorf("key is not an ECDSA public key"))
		}

		pubKey, err := curve.NewPublicKey(append([]byte{0x04}, append(ecdsaPub.X.Bytes(), ecdsaPub.Y.Bytes()...)...))
		if err != nil {
			panic(fmt.Errorf("failed to create ECDH public key: %w", err))
		}

		return &KeyFromBase64Output{
			PublicKey: pubKey,
		}

	default:
		panic(fmt.Errorf("invalid returnKey: %s", returnKey))
	}
}
