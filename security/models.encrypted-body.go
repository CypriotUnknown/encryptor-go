package security

import "encoding/json"

type EncryptedBody struct {
	IV   string `json:"iv"`
	Hash string `json:"hash"`
}

func (body *EncryptedBody) UnmarshalEncryptedBody(bytes []byte) error {

	err := json.Unmarshal(bytes, &body)
	if err != nil {
		return err
	}

	return nil
}
