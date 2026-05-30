# authverifier

Biblioteca compartilhada para **validação local de access tokens** EdDSA emitidos
pelo Auth Service (SaaS-access-manager), via JWKS — **sem network call por
request** no caminho feliz.

> Módulo independente (`go.mod` próprio), consumido pelos resource servers para
> validar tokens localmente.
>
> Import: `github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier`

## O que ela faz

- Baixa o JWKS do issuer e **valida a assinatura localmente** (Ed25519).
- **Pin de algoritmo** (`EdDSA`) → imune a *algorithm confusion*.
- Valida `iss`, `aud` (deste serviço), `exp`/`nbf`/`iat` com leeway.
- `kid` usado só como **lookup** de chave; thumbprint reconferido (RFC 8037).
- Cliente JWKS resiliente: cache local, refresh em background, **single-flight**,
  **cooldown anti-DOS** para `kid` desconhecido, `ETag`/`304`.
- Gancho **opcional** de revogação (Camada 2); ausente = stateless puro.

## As duas camadas de revogação

| | Camada 1 (default) | Camada 2 (opcional) |
|---|---|---|
| Config | `Revocation: nil` | `Revocation: <checker>` |
| Network por request | **zero** | 1 leitura (ex.: Redis) |
| Janela de revogação | TTL do access (~10min) | quase instantânea |
| Quando usar | maioria das rotas | rotas sensíveis / emergência |

A Camada 2 é **Fail-Closed**: se o backend de revogação cair, o token é negado.

## Uso (gin)

```go
ctx := context.Background()

verifier, err := authverifier.New(ctx, authverifier.Config{
    JWKSURI:  "https://auth.exemplo.com/.well-known/jwks.json",
    Issuer:   "saas-access-manager",
    Audience: "billing-service", // o audience DESTE serviço
    // Revocation: redisChecker,  // opcional (Camada 2)
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

## Configuração

| Campo | Obrigatório | Default | Descrição |
|---|---|---|---|
| `JWKSURI` | sim | — | endpoint JWKS (https) |
| `Issuer` | sim | — | `iss` esperado |
| `Audience` | sim | — | `aud` que este serviço exige |
| `Leeway` | não | 30s | tolerância de clock skew |
| `RefreshInterval` | não | 5m | refresh proativo do JWKS |
| `UnknownKIDCooldown` | não | 20s | anti-DOS em cache miss |
| `AllowInsecureHTTP` | não | false | permite `http://` (só dev local) |
| `Revocation` | não | nil | checker da Camada 2 |

## Arquitetura

Hexagonal, espelhando o serviço principal:

```
authverifier.go            facade: New(Config) -> input.TokenVerifier
core/
  domain/{model,errs}      Claims, JWK/JWKS, erros de domínio
  port/input               TokenVerifier
  port/output              KeySetProvider, TokenDecoder, RevocationChecker
  usecase                  VerifyUseCase (decode -> revogação)
adapter/
  output/jwks              cliente JWKS resiliente (KeySetProvider)
  output/jwtdecoder        validação golang-jwt (TokenDecoder)
  input/{httpmw,ginmw}     middlewares
```

Para casos avançados (chaves estáticas em teste, outra origem de JWKS), monte os
ports de `core/port/*` manualmente em vez de usar a facade.

## Implementando a Camada 2

```go
type redisRevocation struct{ rdb *redis.Client }

func (r redisRevocation) IsRevoked(ctx context.Context, c *model.Claims) (bool, error) {
    // blocklist por jti
    if n, err := r.rdb.Exists(ctx, "blocklist:jwt:"+c.JTI).Result(); err != nil {
        return false, err // Fail-Closed: erro propaga -> token negado
    } else if n > 0 {
        return true, nil
    }
    // cursor de revogação global por subject
    cursor, err := r.rdb.Get(ctx, "session:revoked:"+c.Subject).Result()
    if err == redis.Nil {
        return false, nil
    }
    if err != nil {
        return false, err
    }
    epoch, _ := strconv.ParseInt(cursor, 10, 64)
    return c.IssuedAt.Before(time.Unix(epoch, 0)), nil
}
```

> As chaves (`blocklist:jwt:`, `session:revoked:`) batem com as que o Auth
> Service já grava — basta apontar para o mesmo Redis.
