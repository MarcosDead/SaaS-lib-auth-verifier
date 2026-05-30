// Package httpmw adapta o TokenVerifier a um middleware net/http padrão —
// utilizável por qualquer framework compatível com http.Handler, sem puxar
// dependências extras.
package httpmw

import (
	"context"
	"net/http"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/input"
)

const authorizationHeader = "Authorization"

type contextKey struct{}

// claimsKey identifica as claims autenticadas no context.Context da requisição.
var claimsKey = contextKey{}

// RequireAuth devolve um middleware que valida o Bearer token e injeta as claims
// no contexto. Falha => 401 com corpo genérico (sem vazar o motivo).
func RequireAuth(verifier input.TokenVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get(authorizationHeader)
			claims, err := verifier.Verify(r.Context(), header)
			if err != nil {
				http.Error(w, `{"message":"Invalid token"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFrom recupera as claims injetadas pelo middleware (nil se ausente).
func ClaimsFrom(ctx context.Context) *model.Claims {
	if claims, ok := ctx.Value(claimsKey).(*model.Claims); ok {
		return claims
	}
	return nil
}
