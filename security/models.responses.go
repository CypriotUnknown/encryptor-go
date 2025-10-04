package security

import "crypto/ecdh"

type SecurityKeysOutput struct {
	PrivateKeyString string           `json:"privateKeyString"`
	PublicKeyString  string           `json:"publicKeyString"`
	PrivateKey       *ecdh.PrivateKey `json:"-"`
}

type KeyFromBase64Output struct {
	PrivateKey *ecdh.PrivateKey `json:"-"`
	PublicKey  *ecdh.PublicKey  `json:"-"`
}
