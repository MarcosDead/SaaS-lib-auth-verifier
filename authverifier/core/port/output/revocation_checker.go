package output

import (
	"context"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
)

// RevocationChecker é o gancho OPCIONAL da Camada 2 de revogação. nil = stateless
// puro (Camada 1): a janela de revogação é o TTL do access token, sem network
// por request. Wireado, permite revogação mais forte que o TTL — tipicamente
// contra um Redis compartilhado (blocklist por jti + cursor de revogação por
// subject) ou um set em memória alimentado por pub/sub.
//
// IMPORTANTE: implementações devem ser Fail-Closed. Se o backend de revogação
// estiver indisponível, retornar erro (que o use case traduz em ErrInvalidToken)
// em vez de assumir "não revogado" — negar é mais seguro que aceitar às cegas.
type RevocationChecker interface {
	IsRevoked(ctx context.Context, claims *model.Claims) (bool, error)
}
