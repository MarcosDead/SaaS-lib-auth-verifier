// Package authverifier valida localmente, via JWKS, os access tokens de um
// emissor OIDC — sem network call por request no caminho feliz. Não depende de
// provedor: qualquer emissor que publique JWKS e siga o contrato de claims do
// README serve.
//
// É uma facade sobre uma arquitetura hexagonal: New monta os adapters padrão
// (cliente JWKS resiliente + decoder golang-jwt) por trás do port TokenVerifier.
// Para casos avançados (chaves estáticas em teste, outra origem de JWKS), monte
// os ports de core/port/* manualmente.
//
// Uso típico (gin):
//
//	v, err := authverifier.New(ctx, authverifier.Config{
//	    JWKSURI:  "https://auth.exemplo.com/realms/saas/protocol/openid-connect/certs",
//	    Issuer:   "https://auth.exemplo.com/realms/saas",
//	    Audience: "saas-api",
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

// supportedAlgorithms são os algoritmos assimétricos cujas chaves o cliente JWKS
// sabe ler. Nenhum HS*: com eles a chave pública viraria segredo.
var supportedAlgorithms = map[string]bool{"EdDSA": true, "RS256": true, "RS384": true, "RS512": true}

// Config é a configuração da facade.
type Config struct {
	// Obrigatórios.
	JWKSURI  string // jwks_uri do emissor
	Issuer   string // iss esperado nos tokens
	Audience string // aud que ESTE serviço exige nos tokens de usuário

	// Obrigatória para NewPair e NewService: aud dos tokens de serviço aceitos
	// por ESTE serviço (ex.: "likes-manager-internal").
	ServiceAudience string

	// Emissor dos tokens de serviço, quando difere do de usuário (migração entre
	// provedores). Vazios = os mesmos JWKSURI e Issuer.
	ServiceJWKSURI string
	ServiceIssuer  string

	// Opcionais.
	Algorithms         []string      // assinaturas aceitas (default EdDSA)
	Leeway             time.Duration // clock skew tolerado (default 30s)
	RefreshInterval    time.Duration // refresh proativo do JWKS (default 5m)
	UnknownKIDCooldown time.Duration // anti-DOS em cache miss (default 20s)
	AllowInsecureHTTP  bool          // permite JWKSURI http:// (dev local)
}

// New monta o verificador de usuário e aquece o cache de chaves de forma
// síncrona; o refresh em background vive até ctx ser cancelado. Erro no warm-up
// é retornado (fail-fast no boot).
func New(ctx context.Context, cfg Config) (input.TokenVerifier, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	client, err := startKeys(ctx, cfg, cfg.JWKSURI)
	if err != nil {
		return nil, err
	}
	return usecase.NewVerifyUseCase(decoderFor(client, cfg, cfg.Issuer, cfg.Audience)), nil
}

// NewPair devolve o verificador de usuário e o de serviço. Cada um exige sua
// audience, então um token de sessão não passa numa rota interna nem o
// contrário — a separação é criptográfica, não de rede.
func NewPair(ctx context.Context, cfg Config) (input.TokenVerifier, input.ServiceTokenVerifier, error) {
	if err := cfg.validate(); err != nil {
		return nil, nil, err
	}
	if cfg.ServiceAudience == "" {
		return nil, nil, fmt.Errorf("authverifier: ServiceAudience é obrigatória para o canal de serviço")
	}

	client, err := startKeys(ctx, cfg, cfg.JWKSURI)
	if err != nil {
		return nil, nil, err
	}
	service, err := serviceVerifier(ctx, cfg, client)
	if err != nil {
		return nil, nil, err
	}
	return usecase.NewVerifyUseCase(decoderFor(client, cfg, cfg.Issuer, cfg.Audience)), service, nil
}

// NewService serve o serviço que só recebe chamadas de outros serviços.
func NewService(ctx context.Context, cfg Config) (input.ServiceTokenVerifier, error) {
	if uri, issuer := cfg.serviceIssuer(); uri == "" || issuer == "" || cfg.ServiceAudience == "" {
		return nil, fmt.Errorf("authverifier: JWKSURI, Issuer e ServiceAudience são obrigatórios")
	}
	if err := validAlgorithms(cfg.Algorithms); err != nil {
		return nil, err
	}
	return serviceVerifier(ctx, cfg, nil)
}

func (cfg Config) validate() error {
	if cfg.JWKSURI == "" || cfg.Issuer == "" || cfg.Audience == "" {
		return fmt.Errorf("authverifier: JWKSURI, Issuer e Audience são obrigatórios")
	}
	return validAlgorithms(cfg.Algorithms)
}

func validAlgorithms(algs []string) error {
	for _, alg := range algs {
		if !supportedAlgorithms[alg] {
			return fmt.Errorf("authverifier: algoritmo não suportado %q", alg)
		}
	}
	return nil
}

func (cfg Config) serviceIssuer() (jwksURI, issuer string) {
	jwksURI, issuer = cfg.ServiceJWKSURI, cfg.ServiceIssuer
	if jwksURI == "" {
		jwksURI = cfg.JWKSURI
	}
	if issuer == "" {
		issuer = cfg.Issuer
	}
	return jwksURI, issuer
}

// serviceVerifier reaproveita o cliente JWKS de usuário quando o emissor é o mesmo.
func serviceVerifier(ctx context.Context, cfg Config, userKeys *jwks.Client) (input.ServiceTokenVerifier, error) {
	uri, issuer := cfg.serviceIssuer()
	keys := userKeys
	if keys == nil || uri != cfg.JWKSURI {
		var err error
		if keys, err = startKeys(ctx, cfg, uri); err != nil {
			return nil, err
		}
	}
	return usecase.NewVerifyServiceUseCase(decoderFor(keys, cfg, issuer, cfg.ServiceAudience)), nil
}

func startKeys(ctx context.Context, cfg Config, uri string) (*jwks.Client, error) {
	client, err := jwks.NewClient(jwks.Config{
		URI:                uri,
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

func decoderFor(client *jwks.Client, cfg Config, issuer, audience string) output.TokenDecoder {
	algorithms := cfg.Algorithms
	if len(algorithms) == 0 {
		algorithms = []string{"EdDSA"}
	}
	return jwtdecoder.New(client, jwtdecoder.Config{
		Issuer:     issuer,
		Audience:   audience,
		Algorithms: algorithms,
		Leeway:     orDefault(cfg.Leeway, defaultLeeway),
	})
}

func orDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
