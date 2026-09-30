// Package servicetoken obtém tokens de serviço pelo grant client_credentials
// (RFC 6749 §4.4) no token endpoint do emissor e os reaproveita até perto do
// vencimento. A ponta verificadora é o ginmw.RequireServiceScope.
package servicetoken

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// renewMargin renova antes do vencimento para uma chamada não sair com um token
// que expira no caminho.
const renewMargin = 10 * time.Second

type Config struct {
	TokenURL     string // token endpoint do emissor
	ClientID     string
	ClientSecret string
	Scope        string // opcional: vazio = os escopos padrão do client
	HTTPClient   *http.Client
}

// Provider é seguro para uso concorrente. Uma renovação por vez: sob rajada, as
// demais chamadas esperam a que já está no ar em vez de abrir uma cada.
type Provider struct {
	cfg    Config
	client *http.Client

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func New(cfg Config) (*Provider, error) {
	if cfg.TokenURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("servicetoken: TokenURL, ClientID e ClientSecret são obrigatórios")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &Provider{cfg: cfg, client: client}, nil
}

// Token devolve um token válido, emitindo um novo só quando o atual venceu.
func (p *Provider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.token != "" && time.Now().Before(p.expiresAt) {
		return p.token, nil
	}

	token, ttl, err := p.issue(ctx)
	if err != nil {
		return "", err
	}

	p.token = token
	p.expiresAt = time.Now().Add(ttl - renewMargin)
	return token, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (p *Provider) issue(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if p.cfg.Scope != "" {
		form.Set("scope", p.cfg.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))

	resp, err := p.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("servicetoken: token endpoint respondeu %d", resp.StatusCode)
	}

	var issued tokenResponse
	if err := json.UnmarshalRead(resp.Body, &issued); err != nil {
		return "", 0, err
	}
	if issued.AccessToken == "" || issued.ExpiresIn <= 0 {
		return "", 0, fmt.Errorf("servicetoken: resposta sem token utilizável")
	}

	return issued.AccessToken, time.Duration(issued.ExpiresIn) * time.Second, nil
}
