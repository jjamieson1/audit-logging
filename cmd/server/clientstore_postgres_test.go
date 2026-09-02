package main

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// Test clients are named with this prefix so cleanup can target them exactly.
// A blanket DELETE would be a foot-gun if TEST_DATABASE_URL ever pointed
// somewhere real.
const testClientNamePrefix = "plan-test-"

func newTestClientStore(t *testing.T) *PostgresClientStore {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration tests")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}

	store, err := NewPostgresClientStore(db)
	if err != nil {
		t.Fatalf("NewPostgresClientStore() error: %v", err)
	}

	t.Cleanup(func() {
		if _, err := db.Exec(`DELETE FROM audit_clients WHERE name LIKE $1`, testClientNamePrefix+"%"); err != nil {
			t.Errorf("cleanup failed: %v", err)
		}
		db.Close()
	})

	return store
}

func TestPostgresClientStoreRegisterThenAuthenticate(t *testing.T) {
	store := newTestClientStore(t)

	clientID, token, err := store.Register(testClientNamePrefix+"payments", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	principal, err := store.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if principal.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", principal.ClientID, clientID)
	}
	if principal.Role != RoleClient {
		t.Errorf("Role = %q, want %q", principal.Role, RoleClient)
	}
	if principal.IsAdmin() {
		t.Error("IsAdmin() = true for a client-role principal")
	}
}

func TestPostgresClientStoreRejectsBadTokens(t *testing.T) {
	store := newTestClientStore(t)

	clientID, token, err := store.Register(testClientNamePrefix+"reject", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "malformed", in: "not-a-token"},
		{name: "unknown client id", in: formatToken("ffffffffffffffff", "whatever")},
		{name: "right client wrong secret", in: formatToken(clientID, "wrong-secret")},
		{name: "token with trailing junk", in: token + "x"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Authenticate(tc.in); err == nil {
				t.Fatalf("Authenticate(%q) succeeded, want failure", tc.in)
			}
		})
	}
}

func TestPostgresClientStoreRotateInvalidatesTheOldToken(t *testing.T) {
	store := newTestClientStore(t)

	clientID, oldToken, err := store.Register(testClientNamePrefix+"rotate", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	newToken, err := store.Rotate(clientID)
	if err != nil {
		t.Fatalf("Rotate() error: %v", err)
	}
	if newToken == oldToken {
		t.Fatal("Rotate() returned the same token")
	}

	// Rotation is a hard cutover: the old token stops working immediately.
	if _, err := store.Authenticate(oldToken); err == nil {
		t.Fatal("the pre-rotation token still authenticates")
	}

	principal, err := store.Authenticate(newToken)
	if err != nil {
		t.Fatalf("Authenticate(new) error: %v", err)
	}
	// The id survives, so entries already written stay attributed.
	if principal.ClientID != clientID {
		t.Fatalf("ClientID = %q, want %q", principal.ClientID, clientID)
	}
}

func TestPostgresClientStoreRevoke(t *testing.T) {
	store := newTestClientStore(t)

	clientID, token, err := store.Register(testClientNamePrefix+"revoke", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if err := store.Revoke(clientID); err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}
	if _, err := store.Authenticate(token); err == nil {
		t.Fatal("a revoked token still authenticates")
	}
	// Revoking twice is an error, not a silent success.
	if err := store.Revoke(clientID); err == nil {
		t.Fatal("Revoke() of an already-revoked client succeeded, want error")
	}
	// A revoked client cannot be rotated back into service.
	if _, err := store.Rotate(clientID); err == nil {
		t.Fatal("Rotate() of a revoked client succeeded, want error")
	}
}

func TestPostgresClientStoreRegisterValidation(t *testing.T) {
	store := newTestClientStore(t)

	if _, _, err := store.Register("   ", RoleClient); err == nil {
		t.Error("Register() with a blank name succeeded, want error")
	}
	if _, _, err := store.Register(testClientNamePrefix+"badrole", "root"); err == nil {
		t.Error("Register() with role \"root\" succeeded, want error")
	}

	// An empty role defaults to client rather than failing.
	_, token, err := store.Register(testClientNamePrefix+"defaultrole", "")
	if err != nil {
		t.Fatalf("Register() with empty role error: %v", err)
	}
	principal, err := store.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if principal.Role != RoleClient {
		t.Fatalf("Role = %q, want %q", principal.Role, RoleClient)
	}
}

func TestPostgresClientStoreListOmitsSecrets(t *testing.T) {
	store := newTestClientStore(t)

	clientID, token, err := store.Register(testClientNamePrefix+"list", RoleAdmin)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	summaries, err := store.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}

	var found *ClientSummary
	for i := range summaries {
		if summaries[i].ClientID == clientID {
			found = &summaries[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("List() did not include %q", clientID)
	}
	if found.Role != RoleAdmin {
		t.Errorf("Role = %q, want %q", found.Role, RoleAdmin)
	}
	if found.Revoked {
		t.Error("Revoked = true for a fresh client")
	}
	if found.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	// Nothing in the summary may reconstruct the token.
	_, secret, err := parseToken(token)
	if err != nil {
		t.Fatalf("parseToken() error: %v", err)
	}
	if strings.Contains(found.Name, secret) || strings.Contains(found.ClientID, secret) {
		t.Error("List() leaked the token secret")
	}
}
