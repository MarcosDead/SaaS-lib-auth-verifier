package model

// JWK é uma chave pública no formato JSON Web Key, como recebida do endpoint
// JWKS do issuer. A lib consome chaves de assinatura Ed25519 (OKP) e RSA.
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS é o documento retornado pelo jwks_uri do issuer.
type JWKS struct {
	Keys []JWK `json:"keys"`
}
