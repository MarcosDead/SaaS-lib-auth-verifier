# authverifier

Biblioteca compartilhada para **validação local de access tokens** emitidos por
um provedor OIDC, via JWKS — **sem network call por request** no caminho feliz.
Não conhece o provedor: qualquer emissor que publique JWKS e cumpra o
[contrato de claims](#contrato-de-claims) serve.

> Módulo independente (`go.mod` próprio), consumido pelos resource servers.
>
> Import: `github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier`

## O que ela faz

- Baixa o JWKS do emissor e **valida a assinatura localmente** (EdDSA ou RS256).
- **Allowlist de algoritmo** (padrão só `EdDSA`) → imune a *algorithm confusion*;
  HS* nunca é aceito.
- Valida `iss`, `aud` (deste serviço), `exp`/`nbf`/`iat` com leeway.
- `kid` usado só como **lookup** de chave; chaves de cifra (`use: enc`) e tipos
  desconhecidos do JWKS são ignorados.
- Cliente JWKS resiliente: cache local, refresh em background, **single-flight**,
  **cooldown anti-DOS** para `kid` desconhecido, `ETag`/`304`.
- Stateless: a janela de revogação é o TTL do access token.

## Contrato de claims

O que um emissor precisa entregar para os serviços funcionarem sem mudança:

| Claim | Token de usuário | Token de serviço |
|---|---|---|
| `iss` | URL do emissor (`AUTH_ISSUER`) | idem |
| `aud` | `saas-api` (`AUTH_AUDIENCE`) | a audience interna de cada destino (`<servico>-internal`) |
| `sub` | id do usuário (o mesmo id da conta no access-manager) | livre |
| `roles` | lista plana de papéis (`USER`, `SUPER_ADMIN`) | — |
| `type_user` | `PF` ou `PJ` | — |
| `platform` | `WEB` ou `MOBILE` | — |
| `email` | e-mail da conta | — |
| `scope` | livre | escopos concedidos, separados por espaço (RFC 9068) |
| `azp` (ou `client_id`) | — | quem chama |

## Uso (gin)

```go
ctx := context.Background()

verifier, err := authverifier.New(ctx, authverifier.Config{
    JWKSURI:  os.Getenv("AUTH_JWKS_URL"),
    Issuer:   os.Getenv("AUTH_ISSUER"),
    Audience: os.Getenv("AUTH_AUDIENCE"),
})
if err != nil {
    log.Fatal(err)
}

router.Use(ginmw.RequireAuth(verifier))

router.GET("/me", func(c *gin.Context) {
    claims := ginmw.Claims(c)
    c.JSON(200, gin.H{"sub": claims.Subject, "email": claims.String("email")})
})
```

## Uso (net/http)

```go
mux := http.NewServeMux()
protected := httpmw.RequireAuth(verifier)(yourHandler)
mux.Handle("/me", protected)

// dentro do handler:
claims := httpmw.ClaimsFrom(r.Context())
```

## Acessando claims customizadas

`model.Claims` tipa só as registradas (RFC 7519). As demais ficam em `Custom`,
com helpers seguros:

```go
email := claims.String("email")       // "" se ausente
roles := claims.Strings("roles")      // []string normalizado
```

## Papéis

O nome da claim é da lib (`model.ClaimRoles`), e não de cada serviço: o contrato
é um só, então se ele mudar, muda num lugar e todos os consumidores continuam
concordando sobre onde procurar.

```go
claims.HasRole("SUPER_ADMIN")              // comparação exata
claims.HasAnyRole("ADMIN", "SUPER_ADMIN")  // false quando nenhum papel é exigido
```

Como middleware, sempre depois de `RequireAuth`. Sem claims a resposta é 401, e
não 403: quem nem se identificou não teve o acesso negado, ainda não foi
reconhecido.

```go
panel := router.Group("/backoffice")
panel.Use(ginmw.RequireAuth(verifier), ginmw.RequireRole("SUPER_ADMIN"))
```

A comparação é sensível a maiúsculas de propósito: papel é identificador, não
texto livre, e aceitar variação deixaria um `super_admin` passar por
`SUPER_ADMIN`.

## Configuração

| Campo | Obrigatório | Default | Descrição |
|---|---|---|---|
| `JWKSURI` | sim | — | `jwks_uri` do emissor (https) |
| `Issuer` | sim | — | `iss` esperado |
| `Audience` | sim (exceto `NewService`) | — | `aud` que este serviço exige do usuário |
| `ServiceAudience` | `NewPair`, `NewService` | — | `aud` dos tokens de serviço deste serviço |
| `ServiceJWKSURI`, `ServiceIssuer` | não | `JWKSURI`, `Issuer` | emissor dos tokens de serviço, quando é outro (troca de provedor) |
| `Algorithms` | não | `["EdDSA"]` | assinaturas aceitas: `EdDSA`, `RS256`, `RS384`, `RS512` |
| `Leeway` | não | 30s | tolerância de clock skew |
| `RefreshInterval` | não | 5m | refresh proativo do JWKS |
| `UnknownKIDCooldown` | não | 20s | anti-DOS em cache miss |
| `AllowInsecureHTTP` | não | false | permite `http://` (só dev local) |

## Canal de serviço

Rotas `/internal` não aceitam o token que o navegador carrega. `NewPair` devolve
os dois verificadores, cada um exigindo sua audience — a separação é
criptográfica, não de rede. Quem só recebe chamadas de serviço usa `NewService`.

```go
user, service, err := authverifier.NewPair(ctx, authverifier.Config{
    JWKSURI:         os.Getenv("AUTH_JWKS_URL"),
    Issuer:          os.Getenv("AUTH_ISSUER"),
    Audience:        os.Getenv("AUTH_AUDIENCE"),         // saas-api
    ServiceAudience: os.Getenv("AUTH_SERVICE_AUDIENCE"), // likes-manager-internal
})

r.Group("/likes").Use(ginmw.RequireAuth(user))
r.Group("/internal/likes").Use(ginmw.RequireServiceScope(service, "likes:read-bulk"))
```

Token de usuário na rota interna => 401 (audience errada). Token de serviço sem
o escopo => 403. `ginmw.ServiceClaims(c)` expõe `Client` (quem chama) e `Scope`.

`Scope` é a lista separada por espaço do RFC 6749, e `HasScope` compara por
token inteiro — `address:read` não satisfaz `address:read-bulk`.

### Obtendo o token (lado chamador)

`servicetoken.Provider` usa o grant `client_credentials` (RFC 6749 §4.4) e
reaproveita o token até perto do vencimento. Um Provider por serviço basta: o
token traz todos os escopos e audiences concedidos ao client.

```go
tokens, err := servicetoken.New(servicetoken.Config{
    TokenURL:     os.Getenv("AUTH_TOKEN_URL"),
    ClientID:     os.Getenv("M2M_CLIENT_ID"),
    ClientSecret: os.Getenv("M2M_CLIENT_SECRET"),
})

token, err := tokens.Token(ctx) // usar como "Bearer "+token
```

## Arquitetura

Hexagonal:

```
authverifier.go            facade: New / NewPair / NewService
core/
  domain/{model,errs}      Claims, ServiceClaims, JWK/JWKS, erros de domínio
  port/input               TokenVerifier, ServiceTokenVerifier
  port/output              KeySetProvider, TokenDecoder
  usecase                  VerifyUseCase, VerifyServiceUseCase
adapter/
  output/jwks              cliente JWKS resiliente (KeySetProvider)
  output/jwtdecoder        validação golang-jwt (TokenDecoder)
  input/{httpmw,ginmw}     middlewares
servicetoken/              client_credentials com cache
```

Para casos avançados (chaves estáticas em teste, outra origem de JWKS), monte os
ports de `core/port/*` manualmente em vez de usar a facade.
