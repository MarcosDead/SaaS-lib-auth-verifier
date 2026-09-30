package model

import "strings"

// ServiceClaims é a identidade de um token de serviço (client credentials):
// quem chama (Client) e o que pode fazer (Scope). Não é sessão.
type ServiceClaims struct {
	Client string
	Scope  string
}

// HasScope compara por token inteiro: "posts:read" não satisfaz "posts:read-owner".
func (c *ServiceClaims) HasScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, granted := range strings.Fields(c.Scope) {
		if granted == scope {
			return true
		}
	}
	return false
}

// ServiceClaimsFrom devolve nil para token sem escopo. O chamador vem de azp
// (OIDC), com client_id como alternativa de emissores que só usam esse nome.
func ServiceClaimsFrom(claims *Claims) *ServiceClaims {
	if claims == nil {
		return nil
	}
	scope := strings.TrimSpace(claims.String("scope"))
	if scope == "" {
		return nil
	}
	client := claims.String("azp")
	if client == "" {
		client = claims.String("client_id")
	}
	return &ServiceClaims{Client: client, Scope: scope}
}
