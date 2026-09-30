package output

import (
	"context"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
)

// TokenDecoder faz a validação criptográfica e das claims registradas:
// allowlist de algoritmo, assinatura via KeySetProvider, e issuer/audience/
// exp/nbf/iat com leeway.
type TokenDecoder interface {
	Decode(ctx context.Context, rawToken string) (*model.Claims, error)
}
