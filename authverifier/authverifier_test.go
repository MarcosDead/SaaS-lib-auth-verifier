package authverifier_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	json "encoding/json/v2"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier"
	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "saas-access-manager"
	testAudience = "billing-service"
)

// jwksServer é um issuer falso: serve um JWKS com a chave dada e conta hits para
// os testes de anti-DOS.
type jwksServer struct {
	pub  ed25519.PublicKey
	kid  string
	hits atomic.Int64
	srv  *httptest.Server
}

func newJWKSServer(t *testing.T, pub ed25519.PublicKey, kid string) *jwksServer {
	t.Helper()
	js := &jwksServer{pub: pub, kid: kid}
	js.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js.hits.Add(1)
		doc := map[string]any{"keys": []map[string]string{{
			"kid": kid, "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"x": base64.RawURLEncoding.EncodeToString(pub),
		}}}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.MarshalWrite(w, doc)
	}))
	t.Cleanup(js.srv.Close)
	return js
}

func ed25519Thumbprint(pub ed25519.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub)
	canonical := fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, x)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func signToken(t *testing.T, priv ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = kid
	raw, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return raw
}

func validClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"sub": "user-1", "iss": testIssuer, "aud": testAudience,
		"jti": "jti-1", "email": "a@b.com", "roles": []string{"admin"},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
}

func setup(t *testing.T) (ed25519.PrivateKey, string, *jwksServer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kid := ed25519Thumbprint(pub)
	return priv, kid, newJWKSServer(t, pub, kid)
}

func TestVerifyHappyPath(t *testing.T) {
	priv, kid, js := setup(t)
	v, err := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience,
		AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	claims, err := v.Verify(context.Background(), "Bearer "+signToken(t, priv, kid, validClaims()))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.String("email") != "a@b.com" {
		t.Fatalf("claims errados: %+v", claims)
	}
	if roles := claims.Strings("roles"); len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("roles errados: %v", roles)
	}
}

func TestHappyPathIsZeroNetwork(t *testing.T) {
	priv, kid, js := setup(t)
	v, _ := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true,
	})
	hitsAfterWarmup := js.hits.Load()

	for i := 0; i < 50; i++ {
		if _, err := v.Verify(context.Background(), signToken(t, priv, kid, validClaims())); err != nil {
			t.Fatalf("Verify %d: %v", i, err)
		}
	}
	if got := js.hits.Load(); got != hitsAfterWarmup {
		t.Fatalf("caminho feliz tocou a rede: %d hits extras", got-hitsAfterWarmup)
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	priv, kid, js := setup(t)
	v, _ := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true,
	})
	claims := validClaims()
	claims["aud"] = "outro-servico"
	if _, err := v.Verify(context.Background(), signToken(t, priv, kid, claims)); err == nil {
		t.Fatal("token com audience errado foi aceito (confused deputy)")
	}
}

func TestExpiredRejected(t *testing.T) {
	priv, kid, js := setup(t)
	v, _ := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true,
	})
	claims := validClaims()
	claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	if _, err := v.Verify(context.Background(), signToken(t, priv, kid, claims)); err == nil {
		t.Fatal("token expirado foi aceito")
	}
}

func TestAlgConfusionRejected(t *testing.T) {
	priv, kid, js := setup(t)
	v, _ := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true,
	})
	_ = priv
	// Forja HS256 usando a chave PÚBLICA conhecida como segredo HMAC.
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims())
	forged.Header["kid"] = kid
	raw, err := forged.SignedString([]byte(js.pub))
	if err != nil {
		t.Fatalf("forjando: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Fatal("VANTAGEM DO ATACANTE: token HS256 forjado foi aceito")
	}
}

func TestUnknownKIDAntiDOS(t *testing.T) {
	priv, kid, js := setup(t)
	_ = priv
	_ = kid
	v, _ := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience,
		AllowInsecureHTTP: true, UnknownKIDCooldown: time.Hour, // cooldown longo: trava o flood
	})
	hitsAfterWarmup := js.hits.Load()

	// Enxurrada de tokens com kid aleatório (cada um exige uma chave inexistente).
	for i := 0; i < 100; i++ {
		bogus := signToken(t, priv, "kid-aleatorio-"+fmt.Sprint(i), validClaims())
		if _, err := v.Verify(context.Background(), bogus); err == nil {
			t.Fatal("token com kid desconhecido foi aceito")
		}
	}
	// O cooldown deve permitir no máximo UM refresh extra apesar das 100 tentativas.
	extra := js.hits.Load() - hitsAfterWarmup
	if extra > 1 {
		t.Fatalf("anti-DOS falhou: %d refreshes para 100 kids desconhecidos", extra)
	}
}

func TestRotationPickedUpOnUnknownKID(t *testing.T) {
	// Cliente conhece a chave A; o issuer rotaciona para B; um token assinado com
	// B deve ser aceito após o refresh disparado pelo kid desconhecido.
	pubA, privA, _ := ed25519.GenerateKey(nil)
	kidA := ed25519Thumbprint(pubA)
	js := newJWKSServer(t, pubA, kidA)

	v, err := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience,
		AllowInsecureHTTP: true, UnknownKIDCooldown: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = privA

	// Rotaciona o issuer para a chave B.
	pubB, privB, _ := ed25519.GenerateKey(nil)
	kidB := ed25519Thumbprint(pubB)
	js.pub, js.kid = pubB, kidB
	js.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js.hits.Add(1)
		doc := map[string]any{"keys": []map[string]string{{
			"kid": kidB, "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"x": base64.RawURLEncoding.EncodeToString(pubB),
		}}}
		_ = json.MarshalWrite(w, doc)
	})

	time.Sleep(2 * time.Nanosecond)
	if _, err := v.Verify(context.Background(), signToken(t, privB, kidB, validClaims())); err != nil {
		t.Fatalf("token da chave rotacionada foi rejeitado: %v", err)
	}
}

func TestHTTPSRequiredByDefault(t *testing.T) {
	if _, err := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: "http://insecure.example/jwks.json", Issuer: testIssuer, Audience: testAudience,
	}); err == nil {
		t.Fatal("JWKS URI http:// foi aceita sem AllowInsecureHTTP")
	}
}

// Emissores que não derivam o kid do thumbprint, publicam chaves RSA
// e de cifra no mesmo JWKS. O que vale é a chave de assinatura achada pelo kid.
func TestProviderStyleJWKSWithRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	encKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(nil)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.MarshalWrite(w, map[string]any{"keys": []map[string]string{
			rsaJWK("sig-rsa", "sig", &rsaKey.PublicKey),
			rsaJWK("enc-rsa", "enc", &encKey.PublicKey),
			{"kid": "ed-arbitrario", "kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(edPub)},
			{"kid": "ec", "kty": "EC", "crv": "P-256"},
		}})
	}))
	t.Cleanup(srv.Close)

	v, err := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: srv.URL, Issuer: testIssuer, Audience: testAudience,
		Algorithms: []string{"RS256"}, AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := v.Verify(context.Background(), signRSA(t, rsaKey, "sig-rsa", validClaims())); err != nil {
		t.Fatalf("token RS256 rejeitado: %v", err)
	}
	if _, err := v.Verify(context.Background(), signRSA(t, encKey, "enc-rsa", validClaims())); err == nil {
		t.Fatal("token assinado com chave de cifra foi aceito")
	}
}

func TestAlgorithmOutsideAllowlistRejected(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.MarshalWrite(w, map[string]any{"keys": []map[string]string{rsaJWK("k", "sig", &rsaKey.PublicKey)}})
	}))
	t.Cleanup(srv.Close)

	v, err := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: srv.URL, Issuer: testIssuer, Audience: testAudience, AllowInsecureHTTP: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(context.Background(), signRSA(t, rsaKey, "k", validClaims())); err == nil {
		t.Fatal("RS256 aceito com a allowlist padrão (EdDSA)")
	}
}

func TestSymmetricAlgorithmConfigRejected(t *testing.T) {
	_, _, js := setup(t)
	if _, err := authverifier.New(context.Background(), authverifier.Config{
		JWKSURI: js.srv.URL, Issuer: testIssuer, Audience: testAudience,
		Algorithms: []string{"HS256"}, AllowInsecureHTTP: true,
	}); err == nil {
		t.Fatal("HS256 aceito na configuração")
	}
}

func rsaJWK(kid, use string, pub *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kid": kid, "kty": "RSA", "use": use, "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func signRSA(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	return raw
}
