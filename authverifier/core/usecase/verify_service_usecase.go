package usecase

import (
	"context"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/errs"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/input"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/output"
)

// VerifyServiceUseCase valida tokens de serviço. O decoder recebido exige a
// audience interna do serviço, então um token de usuário já é rejeitado ali; a
// ausência de scope é a segunda barreira.
type VerifyServiceUseCase struct {
	decoder output.TokenDecoder
}

func NewVerifyServiceUseCase(decoder output.TokenDecoder) input.ServiceTokenVerifier {
	return &VerifyServiceUseCase{decoder: decoder}
}

func (v *VerifyServiceUseCase) VerifyService(ctx context.Context, bearer string) (*model.ServiceClaims, error) {
	claims, err := v.decoder.Decode(ctx, bearer)
	if err != nil {
		return nil, err
	}

	service := model.ServiceClaimsFrom(claims)
	if service == nil {
		return nil, errs.ErrInvalidToken
	}
	return service, nil
}
