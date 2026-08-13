// Package authverifier oferece validação local de access tokens EdDSA emitidos
// pelo Auth Service, via JWKS — sem network call por request no caminho feliz.
//
// É uma facade sobre uma arquitetura hexagonal: New monta os adapters padrão
// (cliente JWKS resiliente + decoder golang-jwt) por trás do port TokenVerifier.
// Para casos avançados (chaves estáticas em teste, outra origem de JWKS, outro
// backend de revogação), monte os ports de core/port/* manualmente.
//
// Uso típico (gin):
//
//	v, err := authverifier.New(ctx, authverifier.Config{
//	    JWKSURI:  "https://auth.exemplo.com/.well-known/jwks.json",
//	    Issuer:   "saas-access-manager",
//	    Audience: "billing-service", // o audience DESTE serviço
//	})
//	if err != nil { log.Fatal(err) }
//	router.Use(ginmw.RequireAuth(v))
package authverifier

import (
	"context"
	"fmt"
	"time"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/adapter/output/jwks"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/adapter/output/jwtdecoder"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/input"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/output"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/usecase"
)

const defaultLeeway = 30 * time.Second

// Config é a configuração da facade.
type Config struct {
	// Obrigatórios.
	JWKSURI  string // ex.: https://auth.exemplo.com/.well-known/jwks.json
	Issuer   string // iss esperado nos tokens
	Audience string // aud que ESTE serviço exige (confused-deputy guard)

	// Obrigatória só para NewPair: aud dos tokens de serviço aceitos por ESTE
	// serviço (ex.: "likes-manager-internal").
	ServiceAudience string

	// Opcionais.
	Leeway             time.Duration            // clock skew tolerado (default 30s)
	RefreshInterval    time.Duration            // refresh proativo do JWKS (default 5m)
	UnknownKIDCooldown time.Duration            // anti-DOS em cache miss (default 20s)
	AllowInsecureHTTP  bool                     // permite JWKSURI http:// (dev local)
	Revocation         output.RevocationChecker // Camada 2 opcional; nil = stateless puro
}

// New monta o verificador e aquece o cache de chaves de forma síncrona; o
// refresh em background vive até ctx ser cancelado. Erro no warm-up é retornado
// (fail-fast no boot).
func New(ctx context.Context, cfg Config) (input.TokenVerifier, error) {
	if cfg.JWKSURI == "" || cfg.Issuer == "" || cfg.Audience == "" {
		return nil, fmt.Errorf("authverifier: JWKSURI, Issuer e Audience são obrigatórios")
	}

	client, err := startKeys(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return usecase.NewVerifyUseCase(decoderFor(client, cfg, cfg.Audience), cfg.Revocation), nil
}

// NewPair devolve o verificador de usuário e o de serviço compartilhando um só
// cliente JWKS. Cada um exige sua audience, então um token de sessão não passa
// numa rota interna nem o contrário — a separação é criptográfica, não de rede.
func NewPair(ctx context.Context, cfg Config) (input.TokenVerifier, input.ServiceTokenVerifier, error) {
	if cfg.JWKSURI == "" || cfg.Issuer == "" || cfg.Audience == "" {
		return nil, nil, fmt.Errorf("authverifier: JWKSURI, Issuer e Audience são obrigatórios")
	}
	if cfg.ServiceAudience == "" {
		return nil, nil, fmt.Errorf("authverifier: ServiceAudience é obrigatória para o canal de serviço")
	}

	client, err := startKeys(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	user := usecase.NewVerifyUseCase(decoderFor(client, cfg, cfg.Audience), cfg.Revocation)
	service := usecase.NewVerifyServiceUseCase(decoderFor(client, cfg, cfg.ServiceAudience))
	return user, service, nil
}

func startKeys(ctx context.Context, cfg Config) (*jwks.Client, error) {
	client, err := jwks.NewClient(jwks.Config{
		URI:                cfg.JWKSURI,
		RefreshInterval:    cfg.RefreshInterval,
		UnknownKIDCooldown: cfg.UnknownKIDCooldown,
		AllowInsecureHTTP:  cfg.AllowInsecureHTTP,
	})
	if err != nil {
		return nil, fmt.Errorf("authverifier: %w", err)
	}
	if err := client.Start(ctx); err != nil {
		return nil, fmt.Errorf("authverifier: %w", err)
	}
	return client, nil
}

func decoderFor(client *jwks.Client, cfg Config, audience string) output.TokenDecoder {
	return jwtdecoder.New(client, jwtdecoder.Config{
		Issuer:   cfg.Issuer,
		Audience: audience,
		Leeway:   orDefault(cfg.Leeway, defaultLeeway),
	})
}

func orDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
