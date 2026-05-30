package jwks

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
)

const (
	keyTypeOKP = "OKP"
	curveEd255 = "Ed25519"
)

// parseEd25519 converte um JWK OKP/Ed25519 numa chave pública utilizável,
// rejeitando tipos/curvas inesperados e tamanhos inválidos. Como defesa extra
// contra troca silenciosa de chave, exige que o kid declarado seja IGUAL ao
// thumbprint recomputado da própria chave (RFC 8037) — um JWKS adulterado que
// renomeie kids é detectado aqui.
func parseEd25519(jwk model.JWK) (ed25519.PublicKey, error) {
	if jwk.Kty != keyTypeOKP {
		return nil, fmt.Errorf("unsupported kty %q (want %q)", jwk.Kty, keyTypeOKP)
	}
	if jwk.Crv != curveEd255 {
		return nil, fmt.Errorf("unsupported crv %q (want %q)", jwk.Crv, curveEd255)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decoding x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(raw))
	}
	pub := ed25519.PublicKey(raw)

	if jwk.Kid != "" && jwk.Kid != thumbprint(pub) {
		return nil, fmt.Errorf("kid %q does not match key thumbprint", jwk.Kid)
	}
	return pub, nil
}

// thumbprint recomputa o JWK Thumbprint (RFC 7638, perfil OKP da RFC 8037):
// membros obrigatórios crv, kty, x em ordem lexicográfica, sem espaços.
func thumbprint(pub ed25519.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub)
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, curveEd255, keyTypeOKP, x)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
