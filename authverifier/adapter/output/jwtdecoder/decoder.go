package jwtdecoder

import (
	"context"
	"strings"
	"time"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/errs"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/output"
	"github.com/golang-jwt/jwt/v5"
)

const (
	bearerPrefix = "Bearer "
	headerKID    = "kid"
)

// Config parametriza a validação das claims registradas.
type Config struct {
	Issuer     string        // iss esperado (obrigatório)
	Audience   string        // aud que ESTE serviço exige (obrigatório)
	Algorithms []string      // algoritmos de assinatura aceitos (obrigatório)
	Leeway     time.Duration // tolerância de clock skew em exp/nbf/iat
}

// Decoder valida tokens criptograficamente com golang-jwt, resolvendo a chave
// pública pelo kid via KeySetProvider. Stateless e seguro para uso concorrente.
type Decoder struct {
	keys       output.KeySetProvider
	parserOpts []jwt.ParserOption
}

func New(keys output.KeySetProvider, cfg Config) *Decoder {
	opts := []jwt.ParserOption{
		// Pin do algoritmo: defesa central contra algorithm confusion. Sem isto,
		// um atacante poderia forjar alg=none ou alg=HS* usando a chave pública
		// (conhecida) como segredo HMAC.
		jwt.WithValidMethods(cfg.Algorithms),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(cfg.Leeway),
	}
	if cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(cfg.Audience))
	}
	return &Decoder{keys: keys, parserOpts: opts}
}

func (d *Decoder) Decode(ctx context.Context, rawToken string) (*model.Claims, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rawToken), bearerPrefix))
	if raw == "" {
		return nil, errs.ErrInvalidToken
	}

	mapClaims := jwt.MapClaims{}
	token, err := jwt.NewParser(d.parserOpts...).ParseWithClaims(raw, mapClaims, d.keyFunc(ctx))
	if err != nil || !token.Valid {
		return nil, errs.ErrInvalidToken
	}
	return toDomainClaims(mapClaims), nil
}

// keyFunc resolve a chave pública a partir do kid. O kid é input controlado pelo
// atacante: usado EXCLUSIVAMENTE como lookup no KeySetProvider (jamais como
// path/URL/query). O algoritmo já foi conferido contra a allowlist, e a
// golang-jwt recusa uma chave de tipo diferente do algoritmo do header.
func (d *Decoder) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header[headerKID].(string)
		if kid == "" {
			return nil, errs.ErrInvalidToken
		}
		pub, err := d.keys.PublicKey(ctx, kid)
		if err != nil {
			return nil, errs.ErrInvalidToken
		}
		return pub, nil
	}
}

func toDomainClaims(mc jwt.MapClaims) *model.Claims {
	out := &model.Claims{Custom: map[string]any{}}
	for k, v := range mc {
		switch k {
		case "sub":
			out.Subject, _ = v.(string)
		case "iss":
			out.Issuer, _ = v.(string)
		case "jti":
			out.JTI, _ = v.(string)
		case "aud":
			out.Audience = toStringSlice(v)
		case "iat":
			out.IssuedAt = toTime(v)
		case "nbf":
			out.NotBefore = toTime(v)
		case "exp":
			out.ExpiresAt = toTime(v)
		default:
			out.Custom[k] = v
		}
	}
	return out
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// toTime converte um NumericDate JSON (segundos desde epoch, float64) em time.
func toTime(v any) time.Time {
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0).UTC()
	case int64:
		return time.Unix(t, 0).UTC()
	default:
		return time.Time{}
	}
}
