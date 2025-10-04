package security

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"math/big"
)

func (e *Encryptor) generateKeysForBrowser(privateKey *ecdh.PrivateKey) *SecurityKeysOutput {
	// Generate JWK format for browser
	publicKeyJwk, err := e.keyToJWK(&keyToJWKDto{
		publicKey: privateKey.PublicKey(),
		isPrivate: false,
	})
	if err != nil {
		panic(err)
	}
	privateKeyJwk, err := e.privateKeyToJWK(&privateKeyToJWKDto{
		privateKey: privateKey,
	})
	if err != nil {
		panic(err)
	}

	publicKeyBytes, _ := json.Marshal(publicKeyJwk)
	privateKeyBytes, _ := json.Marshal(privateKeyJwk)

	return &SecurityKeysOutput{
		PrivateKeyString: string(privateKeyBytes),
		PublicKeyString:  string(publicKeyBytes),
		PrivateKey:       privateKey,
	}
}

func (e *Encryptor) generateKeysForApp(privateKey *ecdh.PrivateKey) *SecurityKeysOutput {
	pubBytes := privateKey.PublicKey().Bytes()
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(pubBytes[1:33]),
		Y:     big.NewInt(0).SetBytes(pubBytes[33:65]),
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(ecdsaPubKey)
	if err != nil {
		panic(err)
	}

	ecdsaPrivKey := &ecdsa.PrivateKey{
		PublicKey: *ecdsaPubKey,
		D:         big.NewInt(0).SetBytes(privateKey.Bytes()),
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaPrivKey)
	if err != nil {
		panic(err)
	}

	publicKeyString := e.stringUtil.arrayBufferToString(publicKeyBytes, keyEncoding)
	privateKeyString := e.stringUtil.arrayBufferToString(privateKeyBytes, keyEncoding)

	return &SecurityKeysOutput{
		PrivateKeyString: privateKeyString,
		PublicKeyString:  publicKeyString,
		PrivateKey:       privateKey,
	}
}
