package output

import (
	"context"
	"crypto"
)

// KeySetProvider resolve o kid recebido no header de um token para a chave
// pública correspondente, abstraindo a origem das chaves (JWKS HTTP, arquivo,
// chaves estáticas em teste).
//
// O contrato anti-DOS vive aqui: implementações devem coalescer refreshes
// concorrentes (single-flight) e aplicar cooldown para kids desconhecidos, de
// modo que tokens com kid aleatório não consigam martelar o issuer. Para um kid
// que continua ausente após o refresh permitido, devolver errs.ErrKeyNotFound.
type KeySetProvider interface {
	PublicKey(ctx context.Context, kid string) (crypto.PublicKey, error)
}
