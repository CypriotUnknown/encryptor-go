package security

import (
	"encoding/base64"
	"fmt"
)

// Convert public key to JWK format
func (e *Encryptor) keyToJWK(dto *keyToJWKDto) (*JWK, error) {
	pubKeyBytes := dto.publicKey.Bytes()
	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid public key format")
	}

	x := pubKeyBytes[1:33]
	y := pubKeyBytes[33:65]

	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}

	if dto.isPrivate {
		jwk.KeyOps = []string{"deriveBits", "deriveKey"}
	}

	return jwk, nil
}

// Convert private key to JWK format
func (e *Encryptor) privateKeyToJWK(dto *privateKeyToJWKDto) (*JWK, error) {
	jwk, err := e.keyToJWK(&keyToJWKDto{
		publicKey: dto.privateKey.PublicKey(),
		isPrivate: true,
	})
	if err != nil {
		return nil, err
	}

	privateKeyBytes := dto.privateKey.Bytes()
	jwk.D = base64.RawURLEncoding.EncodeToString(privateKeyBytes)

	return jwk, nil
}
