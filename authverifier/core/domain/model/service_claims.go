package model

import "strings"

// ServiceClaims é a identidade de um token de serviço (client credentials).
// Não é sessão: vale para as operações em Scope e, quando o emissor amarra,
// para um recurso só (Target).
type ServiceClaims struct {
	Subject string
	Scope   string
	Target  string
	JTI     string
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

// ServiceClaimsFrom devolve nil quando o token não tem escopo — sinal de que é
// token de usuário, não de serviço.
func ServiceClaimsFrom(claims *Claims) *ServiceClaims {
	if claims == nil {
		return nil
	}
	scope := strings.TrimSpace(claims.String("scope"))
	if scope == "" {
		return nil
	}
	return &ServiceClaims{
		Subject: claims.Subject,
		Scope:   scope,
		Target:  claims.String("target"),
		JTI:     claims.JTI,
	}
}
