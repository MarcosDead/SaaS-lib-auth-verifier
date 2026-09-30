package jwks

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
)

// parseKey aceita as chaves de assinatura que os emissores OIDC publicam:
// OKP/Ed25519 (EdDSA) e RSA (RS256). Chaves de cifra (use=enc) ficam de fora.
func parseKey(jwk model.JWK) (crypto.PublicKey, error) {
	if jwk.Use == "enc" {
		return nil, fmt.Errorf("encryption key %q", jwk.Kid)
	}
	switch jwk.Kty {
	case "OKP":
		return parseEd25519(jwk)
	case "RSA":
		return parseRSA(jwk)
	default:
		return nil, fmt.Errorf("unsupported kty %q", jwk.Kty)
	}
}

func parseEd25519(jwk model.JWK) (ed25519.PublicKey, error) {
	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported crv %q", jwk.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func parseRSA(jwk model.JWK) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < 2048 || pub.E < 3 {
		return nil, fmt.Errorf("weak RSA key %q", jwk.Kid)
	}
	return pub, nil
}
