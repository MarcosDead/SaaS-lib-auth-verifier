package output

import (
	"context"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
)

// TokenDecoder faz a validação criptográfica e das claims registradas: pin do
// algoritmo (apenas EdDSA), assinatura via KeySetProvider, e issuer/audience/
// exp/nbf/iat com leeway. Não conhece revogação — essa é uma camada acima, no
// use case. Separar decode de revogação mantém o crypto isolado e testável.
type TokenDecoder interface {
	Decode(ctx context.Context, rawToken string) (*model.Claims, error)
}
