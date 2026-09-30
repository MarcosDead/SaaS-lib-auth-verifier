package input

import (
	"context"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
)

// TokenVerifier é o port que os serviços consumidores dependem. Recebe o valor
// bruto do header Authorization (com ou sem o prefixo "Bearer ") e devolve a
// identidade autenticada ou errs.ErrInvalidToken.
//
// No caminho feliz, a implementação valida localmente (assinatura + claims) sem
// network call — a chave pública já está em cache. Network só ocorre em refresh
// de JWKS (periódico/em background ou no primeiro kid desconhecido).
type TokenVerifier interface {
	Verify(ctx context.Context, bearer string) (*model.Claims, error)
}
