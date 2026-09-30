package authverifier_test

import (
	"context"
	"testing"
	"time"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/port/input"
	"github.com/golang-jwt/jwt/v5"
)

const testServiceAudience = "billing-service-internal"

func serviceClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"sub": "service-account-1", "azp": "stories-manager", "iss": testIssuer, "aud": testServiceAudience,
		"jti": "svc-1", "scope": "likes:read-bulk posts:read-owner",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
}

func newPair(t *testing.T, js *jwksServer) (input.TokenVerifier, input.ServiceTokenVerifier) {
	t.Helper()
	user, service, err := authverifier.NewPair(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience,
		ServiceAudience: testServiceAudience, AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewPair: %v", err)
	}
	return user, service
}

func TestServiceTokenAccepted(t *testing.T) {
	priv, kid, js := setup(t)
	_, service := newPair(t, js)

	claims, err := service.VerifyService(context.Background(), signToken(t, priv, kid, serviceClaims()))
	if err != nil {
		t.Fatalf("VerifyService: %v", err)
	}
	if claims.Client != "stories-manager" {
		t.Fatalf("client = %q", claims.Client)
	}
	if !claims.HasScope("likes:read-bulk") {
		t.Fatal("escopo concedido não reconhecido")
	}
	if claims.HasScope("likes:read") {
		t.Fatal("escopo casou por prefixo — deve ser por token inteiro")
	}
}

// É a garantia central: o token que o navegador carrega não alcança rota interna.
func TestUserTokenRejectedOnServiceChannel(t *testing.T) {
	priv, kid, js := setup(t)
	_, service := newPair(t, js)

	if _, err := service.VerifyService(context.Background(), signToken(t, priv, kid, validClaims())); err == nil {
		t.Fatal("token de usuário foi aceito no canal de serviço")
	}
}

func TestServiceTokenRejectedOnUserChannel(t *testing.T) {
	priv, kid, js := setup(t)
	user, _ := newPair(t, js)

	if _, err := user.Verify(context.Background(), signToken(t, priv, kid, serviceClaims())); err == nil {
		t.Fatal("token de serviço foi aceito no canal de usuário")
	}
}

// Sem scope não é token de serviço, mesmo com a audience interna correta.
func TestServiceTokenWithoutScopeRejected(t *testing.T) {
	priv, kid, js := setup(t)
	_, service := newPair(t, js)

	claims := serviceClaims()
	delete(claims, "scope")

	if _, err := service.VerifyService(context.Background(), signToken(t, priv, kid, claims)); err == nil {
		t.Fatal("token sem escopo foi aceito")
	}
}

func TestServiceTokenExpiredRejected(t *testing.T) {
	priv, kid, js := setup(t)
	_, service := newPair(t, js)

	claims := serviceClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()

	if _, err := service.VerifyService(context.Background(), signToken(t, priv, kid, claims)); err == nil {
		t.Fatal("token expirado foi aceito")
	}
}

func TestNewPairRequiresServiceAudience(t *testing.T) {
	_, _, js := setup(t)

	_, _, err := authverifier.NewPair(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true,
	})
	if err == nil {
		t.Fatal("NewPair aceitou configuração sem ServiceAudience")
	}
}

// Durante a troca de emissor, o token de serviço vem de um e o de usuário de outro.
func TestServiceIssuerCanDifferFromUserIssuer(t *testing.T) {
	userPriv, userKid, userJWKS := setup(t)
	svcPriv, svcKid, svcJWKS := setup(t)

	user, service, err := authverifier.NewPair(context.Background(), authverifier.Config{
		JWKSURI: userJWKS.srv.URL, Issuer: testIssuer, Audience: testAudience,
		ServiceJWKSURI: svcJWKS.srv.URL, ServiceIssuer: "https://idp/realms/saas",
		ServiceAudience: testServiceAudience, AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewPair: %v", err)
	}

	svc := serviceClaims()
	svc["iss"] = "https://idp/realms/saas"
	if _, err := service.VerifyService(context.Background(), signToken(t, svcPriv, svcKid, svc)); err != nil {
		t.Fatalf("token do novo emissor rejeitado: %v", err)
	}
	if _, err := service.VerifyService(context.Background(), signToken(t, userPriv, userKid, serviceClaims())); err == nil {
		t.Fatal("token de serviço do emissor antigo aceito")
	}
	if _, err := user.Verify(context.Background(), signToken(t, userPriv, userKid, validClaims())); err != nil {
		t.Fatalf("token de usuário rejeitado: %v", err)
	}
}

func TestNewServiceOnly(t *testing.T) {
	priv, kid, js := setup(t)
	service, err := authverifier.NewService(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, ServiceAudience: testServiceAudience, AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := service.VerifyService(context.Background(), signToken(t, priv, kid, serviceClaims())); err != nil {
		t.Fatalf("VerifyService: %v", err)
	}
	if _, err := service.VerifyService(context.Background(), signToken(t, priv, kid, validClaims())); err == nil {
		t.Fatal("token de usuário aceito no NewService")
	}
}
