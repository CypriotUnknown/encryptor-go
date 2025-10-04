package security

import (
	"encoding/base64"
	"encoding/hex"
)

type stringUtility struct{}

func (su *stringUtility) arrayBufferToString(buffer []byte, encoding string) string {
	switch encoding {
	case "base64":
		return base64.StdEncoding.EncodeToString(buffer)
	case "hex":
		return hex.EncodeToString(buffer)
	default:
		return string(buffer)
	}
}

func (su *stringUtility) stringToArrayBuffer(str string, encoding string) ([]byte, error) {
	switch encoding {
	case "base64":
		return base64.StdEncoding.DecodeString(str)
	case "hex":
		return hex.DecodeString(str)
	default:
		return []byte(str), nil
	}
}
