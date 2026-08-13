package input

import (
	"context"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
)

// ServiceTokenVerifier valida um token de serviço. Rejeita token de usuário: a
// audience interna exigida na construção não é emitida para sessões.
type ServiceTokenVerifier interface {
	VerifyService(ctx context.Context, bearer string) (*model.ServiceClaims, error)
}
