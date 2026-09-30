package ginmw

import (
	"net/http"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/input"
	"github.com/gin-gonic/gin"
)

const contextKeyServiceClaims = "auth.service.claims"

// RequireServiceScope protege rotas máquina-a-máquina. Token inválido ou de
// usuário => 401; escopo ausente => 403.
func RequireServiceScope(verifier input.ServiceTokenVerifier, scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := verifier.VerifyService(c.Request.Context(), c.GetHeader(authorizationHeader))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			return
		}
		if !claims.HasScope(scope) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Forbidden"})
			return
		}
		c.Set(contextKeyServiceClaims, claims)
		c.Next()
	}
}

// ServiceClaims recupera as claims de serviço do contexto (nil se ausente).
func ServiceClaims(c *gin.Context) *model.ServiceClaims {
	if v, ok := c.Get(contextKeyServiceClaims); ok {
		if claims, ok := v.(*model.ServiceClaims); ok {
			return claims
		}
	}
	return nil
}
