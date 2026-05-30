// Package ginmw adapta o TokenVerifier a um middleware gin. Fica num subpacote
// separado: só quem o importa passa a depender de gin, mantendo o core leve.
package ginmw

import (
	"net/http"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/input"
	"github.com/gin-gonic/gin"
)

const (
	authorizationHeader = "Authorization"
	// contextKeyClaims é onde as claims autenticadas ficam no gin.Context.
	contextKeyClaims = "auth.claims"
)

// RequireAuth valida o Bearer token e, em sucesso, guarda as claims no contexto
// do gin. Falha => 401 e aborta a cadeia.
func RequireAuth(verifier input.TokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := verifier.Verify(c.Request.Context(), c.GetHeader(authorizationHeader))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			return
		}
		c.Set(contextKeyClaims, claims)
		c.Next()
	}
}

// Claims recupera as claims autenticadas do gin.Context (nil se ausente).
func Claims(c *gin.Context) *model.Claims {
	if v, ok := c.Get(contextKeyClaims); ok {
		if claims, ok := v.(*model.Claims); ok {
			return claims
		}
	}
	return nil
}

// Subject é um atalho para o id do usuário autenticado.
func Subject(c *gin.Context) string {
	if claims := Claims(c); claims != nil {
		return claims.Subject
	}
	return ""
}
