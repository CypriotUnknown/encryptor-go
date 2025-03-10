package encryptor

import (
	"bytes"
	"crypto/ecdh"
	"encoding/asn1"
	"errors"
)

// Helper functions for PKCS7 padding.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("invalid padding length")
	}
	for i := 0; i < padLen; i++ {
		if data[len(data)-1-i] != byte(padLen) {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}

// marshalSPKI builds the DER-encoded SPKI structure from an ECDH public key.
func marshalSPKI(pub *ecdh.PublicKey) ([]byte, error) {
	pubBytes := pub.Bytes()
	spki := subjectPublicKeyInfo{
		Algo: algorithmIdentifier{
			Algorithm:  oidEcPublicKey,
			Parameters: oidNamedCurveP256,
		},
		PublicKey: asn1.BitString{
			Bytes:     pubBytes,
			BitLength: 8 * len(pubBytes),
		},
	}
	return asn1.Marshal(spki)
}

// marshalPKCS8 builds the DER-encoded PKCS#8 structure from an ECDH private key.
func marshalPKCS8(priv *ecdh.PrivateKey) ([]byte, error) {
	privBytes := priv.Bytes()

	pubBytes := priv.PublicKey().Bytes()
	ecPriv := ecPrivateKeyASN{
		Version:    1,
		PrivateKey: privBytes,
		PublicKey: asn1.BitString{
			Bytes:     pubBytes,
			BitLength: 8 * len(pubBytes),
		},
	}
	ecPrivDER, err := asn1.Marshal(ecPriv)
	if err != nil {
		return nil, err
	}
	pkcs8Obj := pkcs8{
		Version: 0,
		Algo: algorithmIdentifier{
			Algorithm:  oidEcPublicKey,
			Parameters: oidNamedCurveP256,
		},
		PrivateKey: ecPrivDER,
	}
	return asn1.Marshal(pkcs8Obj)
}

// unmarshalSPKI parses DER-encoded SPKI bytes into an ECDH public key.
func unmarshalSPKI(der []byte) (*ecdh.PublicKey, error) {
	var spki subjectPublicKeyInfo
	_, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, err
	}
	curve := ecdh.P256()
	return curve.NewPublicKey(spki.PublicKey.Bytes)
}

// unmarshalPKCS8 parses DER-encoded PKCS#8 bytes into an ECDH private key.
func unmarshalPKCS8(der []byte) (*ecdh.PrivateKey, error) {
	var pkcs8Obj pkcs8
	_, err := asn1.Unmarshal(der, &pkcs8Obj)
	if err != nil {
		return nil, err
	}
	var ecPriv ecPrivateKeyASN
	_, err = asn1.Unmarshal(pkcs8Obj.PrivateKey, &ecPriv)
	if err != nil {
		return nil, err
	}
	curve := ecdh.P256()
	return curve.NewPrivateKey(ecPriv.PrivateKey)
}
