package models

type SessionStartDto struct {
	PublicKey string `json:"publicKey"`
}
type APIResponse[T any] struct {
	Success bool `json:"success"`
	Data    T    `json:"data"`
	Status  int  `json:"status"`
}
type SessionStartResponseData struct {
	SessionToken    string `json:"sessionToken"`
	ServerPublicKey string `json:"serverPublicKey"`
}
type AccountInfoDTO struct {
	Account string `json:"account"`
}

type EncryptedBodyDTO struct {
	IV   string `json:"iv"`   // base64-encoded IV
	Hash string `json:"hash"` // hex-encoded ciphertext
}
