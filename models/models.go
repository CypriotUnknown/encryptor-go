package models

type EncryptedBody struct {
	IV   string `json:"iv"`   // base64-encoded IV
	Hash string `json:"hash"` // hex-encoded ciphertext
}
