package errs

import "errors"

// Erros do domínio da verificação. Os consumidores devem tratar qualquer um
// deles como 401 — as mensagens são genéricas de propósito (não vazar o motivo
// exato da rejeição evita enumeração e probing por atacantes).
var (
	// ErrInvalidToken cobre toda falha de validação local: assinatura inválida,
	// expirado, issuer/audience errados, alg não permitido, kid desconhecido.
	ErrInvalidToken = errors.New("invalid token")

	// ErrKeyNotFound é interno ao resolver de chaves: o kid do token não está no
	// JWKS em cache nem após refresh. O use case o converte em ErrInvalidToken.
	ErrKeyNotFound = errors.New("signing key not found for kid")
)
