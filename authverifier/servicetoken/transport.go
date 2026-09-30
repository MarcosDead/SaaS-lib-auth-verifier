package servicetoken

import "net/http"

// Transport injeta "Authorization: Bearer <token>" em cada requisição, como o
// oauth2.Transport: o http.Client de uma chamada interna não lida com token.
// Falha ao obter o token vira erro do Do, como uma falha de rede.
func (p *Provider) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{provider: p, base: base}
}

type transport struct {
	provider *Provider
	base     http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.provider.Token(req.Context())
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	authorized := req.Clone(req.Context())
	authorized.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(authorized)
}
