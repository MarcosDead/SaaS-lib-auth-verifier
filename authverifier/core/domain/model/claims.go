package model

import "time"

// Claims é a identidade autenticada extraída de um access token verificado.
//
// A lib é compartilhada por serviços diferentes, então o domínio aqui é
// deliberadamente genérico: registra apenas as claims padronizadas (RFC 7519) e
// expõe as customizadas via Custom, sem conhecer os tipos de negócio de nenhum
// consumidor específico (roles, type_user etc. são responsabilidade de cada um).
type Claims struct {
	Subject   string
	Issuer    string
	Audience  []string
	JTI       string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time

	// Custom carrega as claims não-registradas (ex.: email, roles, type_user).
	// Cada serviço extrai e tipa o que precisa via os helpers abaixo.
	Custom map[string]any
}

// String devolve uma claim customizada como string ("" se ausente ou de outro
// tipo). Evita repetição de type-assertions propensas a panic nos consumidores.
func (c *Claims) String(name string) string {
	if v, ok := c.Custom[name].(string); ok {
		return v
	}
	return ""
}

// Strings devolve uma claim customizada como []string. Aceita tanto um array
// JSON ([]any de strings) quanto uma única string, normalizando ambos.
func (c *Claims) Strings(name string) []string {
	switch v := c.Custom[name].(type) {
	case []string:
		return v
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

const ClaimRoles = "roles"

// Comparação exata: papel é identificador, não texto livre.
func (c *Claims) HasRole(role string) bool {
	if role == "" {
		return false
	}
	for _, r := range c.Strings(ClaimRoles) {
		if r == role {
			return true
		}
	}
	return false
}

func (c *Claims) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if c.HasRole(role) {
			return true
		}
	}
	return false
}

// HasAudience indica se o token foi destinado a um audience específico.
func (c *Claims) HasAudience(aud string) bool {
	for _, a := range c.Audience {
		if a == aud {
			return true
		}
	}
	return false
}
