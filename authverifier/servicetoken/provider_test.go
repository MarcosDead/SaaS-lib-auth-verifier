package servicetoken_test

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	lastForm  url.Values
	lastUser  string
	lastPass  string
}

func newAuthStub(t *testing.T) *authStub {
	t.Helper()
	stub := &authStub{expiresIn: 60, status: http.StatusOK}
	stub.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stub.mu.Lock()
		stub.issued++
		_ = r.ParseForm()
		stub.lastForm = r.PostForm
		stub.lastUser, stub.lastPass, _ = r.BasicAuth()
		status, expiresIn := stub.status, stub.expiresIn
		stub.mu.Unlock()

		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.MarshalWrite(w, map[string]any{
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

// RFC 6749 §4.4: form-urlencoded, credencial do client em Basic, sem scope quando
// o client usa os escopos padrão.
func TestRequestFollowsClientCredentialsGrant(t *testing.T) {
	stub := newAuthStub(t)
	provider := newProvider(t, stub)

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}

	if stub.lastForm.Get("grant_type") != "client_credentials" || stub.lastForm.Has("scope") {
		t.Fatalf("form enviado = %v", stub.lastForm)
	}
	if stub.lastUser != "stories-manager" || stub.lastPass != "s3cr3t" {
		t.Fatalf("basic auth = %q/%q", stub.lastUser, stub.lastPass)
	}
}

func TestScopeIsSentWhenConfigured(t *testing.T) {
	stub := newAuthStub(t)
	provider, err := servicetoken.New(servicetoken.Config{
		TokenURL: stub.srv.URL, ClientID: "stories-manager", ClientSecret: "s3cr3t", Scope: "likes:read-bulk",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	if stub.lastForm.Get("scope") != "likes:read-bulk" {
		t.Fatalf("scope = %q", stub.lastForm.Get("scope"))
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

func TestTransportAuthorizesEachRequest(t *testing.T) {
	stub := newAuthStub(t)
	provider := newProvider(t, stub)

	var got string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	t.Cleanup(target.Close)

	client := provider.Client(&http.Client{})
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()

	if got != "Bearer svc-token" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestTransportFailsWhenTokenIsUnavailable(t *testing.T) {
	stub := newAuthStub(t)
	stub.status = http.StatusUnauthorized
	provider := newProvider(t, stub)

	client := &http.Client{Transport: provider.Transport(nil)}
	if _, err := client.Get("http://127.0.0.1:1"); err == nil {
		t.Fatal("requisição saiu sem token")
	}
}
