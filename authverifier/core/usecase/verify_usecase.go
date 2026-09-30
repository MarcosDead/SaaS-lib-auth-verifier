package usecase

import (
	"context"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/input"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/output"
)

// VerifyUseCase valida o token de usuário: assinatura e claims registradas.
// Stateless — a janela de revogação é o TTL do access token.
type VerifyUseCase struct {
	decoder output.TokenDecoder
}

func NewVerifyUseCase(decoder output.TokenDecoder) input.TokenVerifier {
	return &VerifyUseCase{decoder: decoder}
}

func (v *VerifyUseCase) Verify(ctx context.Context, bearer string) (*model.Claims, error) {
	return v.decoder.Decode(ctx, bearer)
}
