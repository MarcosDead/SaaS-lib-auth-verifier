package model

import "testing"

func TestHasRole(t *testing.T) {
	claims := &Claims{Custom: map[string]any{ClaimRoles: []any{"USER", "SUPER_ADMIN"}}}

	if !claims.HasRole("SUPER_ADMIN") {
		t.Fatal("expected the role to be found")
	}
	if claims.HasRole("ADMIN") {
		t.Fatal("a role that is not there must not be found")
	}
	// Papel é identificador: aceitar variação de caixa deixaria um
	// "super_admin" passar por SUPER_ADMIN.
	if claims.HasRole("super_admin") {
		t.Fatal("role comparison must be case sensitive")
	}
	if claims.HasRole("") {
		t.Fatal("an empty role must never match")
	}
}

// A claim chega como string única quando o token carrega um papel só.
func TestHasRoleAcceptsSingleStringClaim(t *testing.T) {
	claims := &Claims{Custom: map[string]any{ClaimRoles: "SUPER_ADMIN"}}

	if !claims.HasRole("SUPER_ADMIN") {
		t.Fatal("expected a single-string roles claim to be understood")
	}
}

func TestHasAnyRole(t *testing.T) {
	claims := &Claims{Custom: map[string]any{ClaimRoles: []any{"USER"}}}

	if !claims.HasAnyRole("ADMIN", "USER") {
		t.Fatal("expected one of the roles to match")
	}
	if claims.HasAnyRole("ADMIN", "SUPER_ADMIN") {
		t.Fatal("expected no match")
	}
	// Exigir "qualquer um de nada" e liberar seria falha silenciosa.
	if claims.HasAnyRole() {
		t.Fatal("no required role must never authorize")
	}
}

func TestHasRoleWithoutClaim(t *testing.T) {
	if (&Claims{}).HasRole("SUPER_ADMIN") {
		t.Fatal("a token without the roles claim must not authorize")
	}
}
