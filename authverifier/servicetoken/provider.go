// Package servicetoken obtém tokens de serviço (client credentials) no Auth
// Service e os reaproveita até perto do vencimento. É a ponta emissora do canal
// M2M; a verificadora é o ginmw.RequireServiceScope.
package servicetoken

import (
	"bytes"
	"context"
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// renewMargin renova antes do vencimento para uma chamada não sair com um token
// que expira no caminho.
const renewMargin = 10 * time.Second

type Config struct {
	TokenURL     string // POST /auth/token do Auth Service
	ClientID     string
	ClientSecret string
	Scope        string
	Audience     string // serviço de destino; vazio = o próprio Auth Service
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
	if cfg.TokenURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Scope == "" {
		return nil, fmt.Errorf("servicetoken: TokenURL, ClientID, ClientSecret e Scope são obrigatórios")
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

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
	Audience     string `json:"audience,omitempty"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (p *Provider) issue(ctx context.Context) (string, time.Duration, error) {
	body, err := json.Marshal(tokenRequest{
		GrantType:    "client_credentials",
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Scope:        p.cfg.Scope,
		Audience:     p.cfg.Audience,
	})
	if err != nil {
		return "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.TokenURL, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("servicetoken: auth service respondeu %d", resp.StatusCode)
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
