package jwks

import (
	"context"
	"crypto"
	json "encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/errs"
	"github.com/MarcosDead/SaaS-lib-auth-verifier/authverifier/core/domain/model"
)

const (
	defaultRefreshInterval = 5 * time.Minute
	defaultCooldown        = 20 * time.Second
	defaultMaxBytes        = 1 << 20 // 1 MiB — um JWKS legítimo é de KB
	defaultRequestTimeout  = 5 * time.Second
)

// Config parametriza o cliente JWKS.
type Config struct {
	URI                string        // endpoint JWKS do issuer (obrigatório, https)
	HTTPClient         *http.Client  // default: http.Client com timeout
	RefreshInterval    time.Duration // refresh proativo em background (default 5m)
	UnknownKIDCooldown time.Duration // intervalo mínimo entre refreshes forçados por cache miss (default 20s)
	MaxResponseBytes   int64         // limite do corpo da resposta (default 1 MiB)
	RequestTimeout     time.Duration // timeout por requisição (default 5s)
	AllowInsecureHTTP  bool          // permite URI http:// (apenas para dev local)
}

// snapshot é o estado imutável do cache. Trocado atomicamente a cada refresh —
// leituras (PublicKey) são lock-free.
type snapshot struct {
	keys map[string]crypto.PublicKey
	etag string
}

// Client busca e cacheia o JWKS do issuer, resolvendo kid -> chave pública.
//
// Resiliência embutida:
//   - cache local: caminho feliz é zero network;
//   - refresh em background: pega rotações proativamente;
//   - single-flight: refreshes concorrentes coalescem numa única chamada HTTP;
//   - cooldown anti-DOS: uma enxurrada de tokens com kid aleatório dispara no
//     máximo um refresh por janela de cooldown;
//   - ETag/If-None-Match: refreshes periódicos custam 304 quando nada mudou.
type Client struct {
	uri             string
	httpClient      *http.Client
	refreshInterval time.Duration
	cooldown        time.Duration
	maxBytes        int64
	requestTimeout  time.Duration

	snap      atomic.Pointer[snapshot]
	lastFetch atomic.Int64 // unixnano do último acesso à rede (sucesso ou falha)
	sf        singleFlight
}

func NewClient(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.URI))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid JWKS URI %q", cfg.URI)
	}
	if u.Scheme != "https" && !cfg.AllowInsecureHTTP {
		return nil, fmt.Errorf("JWKS URI must be https (set AllowInsecureHTTP for local dev): %q", cfg.URI)
	}

	c := &Client{
		uri:             cfg.URI,
		httpClient:      cfg.HTTPClient,
		refreshInterval: orDurationDefault(cfg.RefreshInterval, defaultRefreshInterval),
		cooldown:        orDurationDefault(cfg.UnknownKIDCooldown, defaultCooldown),
		maxBytes:        orInt64Default(cfg.MaxResponseBytes, defaultMaxBytes),
		requestTimeout:  orDurationDefault(cfg.RequestTimeout, defaultRequestTimeout),
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: c.requestTimeout}
	}
	c.snap.Store(&snapshot{keys: map[string]crypto.PublicKey{}})
	return c, nil
}

// Start aquece o cache com um fetch síncrono e dispara o refresh em background,
// que vive até o ctx ser cancelado. Falha no warm-up é retornada para o caller
// decidir (fail-fast no boot é, em geral, a escolha certa).
func (c *Client) Start(ctx context.Context) error {
	if err := c.fetch(ctx); err != nil {
		return fmt.Errorf("warming JWKS cache: %w", err)
	}
	go c.loop(ctx)
	return nil
}

func (c *Client) loop(ctx context.Context) {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refresh(ctx, true)
		}
	}
}

// PublicKey resolve o kid. Hit no cache = zero network. Miss dispara, no máximo,
// um refresh coordenado (single-flight + cooldown) e re-checa.
func (c *Client) PublicKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if pub, ok := c.snap.Load().keys[kid]; ok {
		return pub, nil
	}
	c.refresh(ctx, false)
	if pub, ok := c.snap.Load().keys[kid]; ok {
		return pub, nil
	}
	return nil, errs.ErrKeyNotFound
}

// refresh coordena o acesso à rede. force=true ignora o cooldown (background);
// force=false respeita o cooldown (caminho de cache miss, anti-DOS). Em ambos,
// chamadas concorrentes coalescem via single-flight.
func (c *Client) refresh(ctx context.Context, force bool) {
	c.sf.Do(func() {
		if !force {
			last := time.Unix(0, c.lastFetch.Load())
			if time.Since(last) < c.cooldown {
				return // refresh recente demais; waiters apenas re-checam o cache
			}
		}
		_ = c.fetch(ctx)
	})
}

func (c *Client) fetch(ctx context.Context) error {
	c.lastFetch.Store(time.Now().UnixNano())

	if c.requestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.requestTimeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.uri, nil)
	if err != nil {
		return err
	}
	if etag := c.snap.Load().etag; etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil // cache permanece válido
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > c.maxBytes {
		return fmt.Errorf("JWKS response exceeds %d bytes", c.maxBytes)
	}

	var doc model.JWKS
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("decoding JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, jwk := range doc.Keys {
		pub, err := parseKey(jwk)
		if err != nil {
			continue // ignora chaves não suportadas/inválidas sem derrubar o set
		}
		keys[jwk.Kid] = pub
	}
	if len(keys) == 0 {
		// Não substituir um cache possivelmente bom por um vazio.
		return fmt.Errorf("JWKS contained no usable signing keys")
	}

	c.snap.Store(&snapshot{keys: keys, etag: resp.Header.Get("ETag")})
	return nil
}

// singleFlight coalesce execuções concorrentes numa só: quem chega durante uma
// execução em voo espera por ela em vez de iniciar outra.
type singleFlight struct {
	mu       sync.Mutex
	inflight *call
}

type call struct{ done chan struct{} }

func (s *singleFlight) Do(fn func()) {
	s.mu.Lock()
	if s.inflight != nil {
		c := s.inflight
		s.mu.Unlock()
		<-c.done
		return
	}
	c := &call{done: make(chan struct{})}
	s.inflight = c
	s.mu.Unlock()

	fn()

	s.mu.Lock()
	s.inflight = nil
	s.mu.Unlock()
	close(c.done)
}

func orDurationDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func orInt64Default(v, def int64) int64 {
	if v <= 0 {
		return def
	}
	return v
}
