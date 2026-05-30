package model

// JWK é uma chave pública no formato JSON Web Key, como recebida do endpoint
// JWKS do issuer. A lib só consome chaves de assinatura Ed25519 (kty=OKP).
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS é o documento retornado por GET /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}
