package ginmw

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequireRole exige um papel. Deve vir depois de RequireAuth: sem claims no
// contexto a resposta é 401, não 403 — quem nem se identificou não teve o
// acesso negado, ainda não foi reconhecido.
func RequireRole(role string) gin.HandlerFunc {
	return RequireAnyRole(role)
}

func RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := Claims(c)
		if claims == nil || claims.Subject == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			return
		}
		if !claims.HasAnyRole(roles...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "Insufficient role"})
			return
		}
		c.Next()
	}
}
