package security

import "crypto/ecdh"

type ComputeSecretDTO struct {
	ClientPublicKeyBase64 string           `json:"clientPublicKeyBase64"`
	PrivateKey            *ecdh.PrivateKey `json:"privateKey"`
	Platform              Platform         `json:"platform"`
}

type DecryptContentDto struct {
	Content  *EncryptedBody `json:"content"`
	Secret   string         `json:"secret"`
	Platform Platform       `json:"platform"`
}

type EncryptContentDto struct {
	Content  string   `json:"content"`
	Secret   string   `json:"secret"`
	Platform Platform `json:"platform"`
}

type keyToJWKDto struct {
	publicKey *ecdh.PublicKey `json:"-"`
	isPrivate bool            `json:"-"`
}

type privateKeyToJWKDto struct {
	privateKey *ecdh.PrivateKey `json:"-"`
}

type GenerateCryptoKeyFromBase64Dto struct {
	Base64KeyString string                `json:"base_64_key_string"`
	Platform        Platform              `json:"platform"`
	ReturnKey       GeneratedKeyReturnKey `json:"return_key"`
}
