package servicetoken_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/servicetoken"
)

type authStub struct {
	srv       *httptest.Server
	issued    int
	expiresIn int
	status    int
	mu        sync.Mutex
	lastBody  map[string]any
}

func newAuthStub(t *testing.T) *authStub {
	t.Helper()
	stub := &authStub{expiresIn: 60, status: http.StatusOK}
	stub.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.issued++
		_ = json.NewDecoder(r.Body).Decode(&stub.lastBody)
		status, expiresIn := stub.status, stub.expiresIn
		stub.mu.Unlock()

		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "svc-token", "expires_in": expiresIn,
		})
	}))
	t.Cleanup(stub.srv.Close)
	return stub
}

func newProvider(t *testing.T, stub *authStub) *servicetoken.Provider {
	t.Helper()
	p, err := servicetoken.New(servicetoken.Config{
		TokenURL: stub.srv.URL, ClientID: "stories-manager", ClientSecret: "s3cr3t",
		Scope: "likes:read-bulk", Audience: "likes-manager-internal",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestTokenIsReusedUntilExpiry(t *testing.T) {
	stub := newAuthStub(t)
	provider := newProvider(t, stub)

	for i := 0; i < 3; i++ {
		if _, err := provider.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}

	if stub.issued != 1 {
		t.Fatalf("emissões = %d; o token deveria ser reaproveitado", stub.issued)
	}
}

// TTL menor que a margem de renovação força emissão a cada chamada — é o que
// mantém a chamada de saindo com um token que vence no caminho.
func TestTokenRenewedWhenWithinMargin(t *testing.T) {
	stub := newAuthStub(t)
	stub.expiresIn = 5
	provider := newProvider(t, stub)

	for i := 0; i < 2; i++ {
		if _, err := provider.Token(context.Background()); err != nil {
			t.Fatalf("Token: %v", err)
		}
	}

	if stub.issued != 2 {
		t.Fatalf("emissões = %d; token perto do vencimento deveria ser renovado", stub.issued)
	}
}

func TestScopeAndAudienceAreSent(t *testing.T) {
	stub := newAuthStub(t)
	provider := newProvider(t, stub)

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}

	if stub.lastBody["scope"] != "likes:read-bulk" || stub.lastBody["audience"] != "likes-manager-internal" {
		t.Fatalf("corpo enviado = %v", stub.lastBody)
	}
	if stub.lastBody["grant_type"] != "client_credentials" {
		t.Fatalf("grant_type = %v", stub.lastBody["grant_type"])
	}
}

func TestAuthFailureIsReported(t *testing.T) {
	stub := newAuthStub(t)
	stub.status = http.StatusUnauthorized
	provider := newProvider(t, stub)

	if _, err := provider.Token(context.Background()); err == nil {
		t.Fatal("falha de emissão não foi reportada")
	}
}

func TestConfigIsValidated(t *testing.T) {
	if _, err := servicetoken.New(servicetoken.Config{TokenURL: "http://x", ClientID: "a"}); err == nil {
		t.Fatal("configuração incompleta foi aceita")
	}
}
