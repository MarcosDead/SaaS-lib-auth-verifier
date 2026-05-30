package usecase

import (
	"context"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/errs"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/input"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/output"
)

// VerifyUseCase orquestra a verificação em duas etapas:
//
//  1. Decode  — assinatura + claims registradas (sempre local, zero network no
//     caminho feliz). É a Camada 1: confiança na assinatura via JWKS.
//  2. Revoke  — checagem OPCIONAL de revogação (Camada 2). Quando o checker é
//     nil, a verificação é stateless pura e a janela de revogação é o TTL.
//
// Separar as duas etapas deixa explícito o trade-off central: "zero network por
// request" (checker nil) vs "revogação mais forte que o TTL" (checker wireado).
type VerifyUseCase struct {
	decoder    output.TokenDecoder
	revocation output.RevocationChecker // pode ser nil
}

func NewVerifyUseCase(decoder output.TokenDecoder, revocation output.RevocationChecker) input.TokenVerifier {
	return &VerifyUseCase{decoder: decoder, revocation: revocation}
}

func (v *VerifyUseCase) Verify(ctx context.Context, bearer string) (*model.Claims, error) {
	claims, err := v.decoder.Decode(ctx, bearer)
	if err != nil {
		return nil, err
	}

	if v.revocation != nil {
		revoked, err := v.revocation.IsRevoked(ctx, claims)
		if err != nil {
			// Fail-Closed: backend de revogação indisponível => negar.
			return nil, errs.ErrInvalidToken
		}
		if revoked {
			return nil, errs.ErrRevoked
		}
	}

	return claims, nil
}
