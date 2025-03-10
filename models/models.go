package models

type EncryptedBody struct {
	IV   string `json:"iv"`
	Hash string `json:"hash"`
}
