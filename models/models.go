package models

import "encoding/json"

type EncryptedBody struct {
	IV   string `json:"iv"`
	Hash string `json:"hash"`
}

func UnmarshalEncryptedBody(bytes []byte) (*EncryptedBody, error) {
	var body EncryptedBody
	err := json.Unmarshal(bytes, &body)
	if err != nil {
		return nil, err
	}

	return &body, nil
}
