package security

type JWK struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	D      string   `json:"d,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}
