package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// memoryClientStore is a working in-memory registry. The fake in
// handlers_test.go only needs Authenticate; the CLI exercises everything else.
type memoryClientStore struct {
	clients map[string]*ClientSummary
	secrets map[string]string
	nextID  int
}

func newMemoryClientStore() *memoryClientStore {
	return &memoryClientStore{
		clients: make(map[string]*ClientSummary),
		secrets: make(map[string]string),
	}
}

func (m *memoryClientStore) Authenticate(token string) (Principal, error) {
	clientID, secret, err := parseToken(token)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	client, ok := m.clients[clientID]
	if !ok || client.Revoked || m.secrets[clientID] != secret {
		return Principal{}, ErrUnauthorized
	}
	return Principal{ClientID: clientID, Name: client.Name, Role: client.Role}, nil
}

func (m *memoryClientStore) Register(name, role string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", errors.New("client name is required")
	}
	if role == "" {
		role = RoleClient
	}
	if !validRole(role) {
		return "", "", fmt.Errorf("invalid role %q", role)
	}

	m.nextID++
	clientID := fmt.Sprintf("%016d", m.nextID)
	secret := fmt.Sprintf("secret-%d", m.nextID)

	m.clients[clientID] = &ClientSummary{
		ClientID:  clientID,
		Name:      name,
		Role:      role,
		CreatedAt: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
	}
	m.secrets[clientID] = secret

	return clientID, formatToken(clientID, secret), nil
}

func (m *memoryClientStore) Rotate(clientID string) (string, error) {
	client, ok := m.clients[clientID]
	if !ok || client.Revoked {
		return "", fmt.Errorf("no active client with id %q", clientID)
	}
	secret := "rotated-" + clientID
	m.secrets[clientID] = secret
	return formatToken(clientID, secret), nil
}

func (m *memoryClientStore) Revoke(clientID string) error {
	client, ok := m.clients[clientID]
	if !ok || client.Revoked {
		return fmt.Errorf("no active client with id %q", clientID)
	}
	client.Revoked = true
	return nil
}

func (m *memoryClientStore) List() ([]ClientSummary, error) {
	summaries := make([]ClientSummary, 0, len(m.clients))
	for _, client := range m.clients {
		summaries = append(summaries, *client)
	}
	return summaries, nil
}

func runCLI(t *testing.T, store ClientStore, args ...string) (string, int) {
	t.Helper()

	var out bytes.Buffer
	code := runClientsCLI(store, args, &out)
	return out.String(), code
}

func TestClientsRegisterPrintsTokenOnceWithAWarning(t *testing.T) {
	store := newMemoryClientStore()

	output, code := runCLI(t, store, "register", "--name", "payments-api")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0. output:\n%s", code, output)
	}

	if !strings.Contains(output, "0000000000000001") {
		t.Errorf("output does not contain the client id:\n%s", output)
	}
	if !strings.Contains(output, "alog_0000000000000001_secret-1") {
		t.Errorf("output does not contain the token:\n%s", output)
	}
	if strings.Count(output, "alog_0000000000000001_secret-1") != 1 {
		t.Errorf("token printed more than once:\n%s", output)
	}
	if !strings.Contains(strings.ToLower(output), "not recoverable") {
		t.Errorf("output does not warn that the token cannot be retrieved again:\n%s", output)
	}
}

func TestClientsRegisterRole(t *testing.T) {
	store := newMemoryClientStore()

	if _, code := runCLI(t, store, "register", "--name", "ops", "--role", "admin"); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	summaries, err := store.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if summaries[0].Role != RoleAdmin {
		t.Fatalf("Role = %q, want %q", summaries[0].Role, RoleAdmin)
	}
}

func TestClientsRegisterRejectsBadInput(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		// A missing or blank --name is a usage error: the CLI never asked the
		// store to do anything.
		{name: "missing name", args: []string{"register"}, wantCode: 2},
		{name: "blank name", args: []string{"register", "--name", "   "}, wantCode: 2},
		// An invalid role reaches the store and is a genuine operation
		// failure, not a usage error.
		{name: "invalid role", args: []string{"register", "--name", "x", "--role", "root"}, wantCode: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, code := runCLI(t, newMemoryClientStore(), tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit code = %d, want %d. output:\n%s", code, tc.wantCode, output)
			}
			if strings.Contains(output, "alog_") {
				t.Fatalf("a token was printed on a failed registration:\n%s", output)
			}
		})
	}
}

func TestClientsListShowsClientsWithoutSecrets(t *testing.T) {
	store := newMemoryClientStore()
	if _, _, err := store.Register("payments-api", RoleClient); err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	output, code := runCLI(t, store, "list")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(output, "payments-api") {
		t.Errorf("list output missing the client name:\n%s", output)
	}
	if !strings.Contains(output, "active") {
		t.Errorf("list output missing the status:\n%s", output)
	}
	// The one thing list must never do.
	if strings.Contains(output, "alog_") || strings.Contains(output, "secret-") {
		t.Errorf("list leaked a token or secret:\n%s", output)
	}
}

func TestClientsListMarksRevoked(t *testing.T) {
	store := newMemoryClientStore()
	clientID, _, err := store.Register("gone", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if err := store.Revoke(clientID); err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}

	output, _ := runCLI(t, store, "list")
	if !strings.Contains(output, "revoked") {
		t.Errorf("list did not mark the revoked client:\n%s", output)
	}
}

func TestClientsRotate(t *testing.T) {
	store := newMemoryClientStore()
	clientID, oldToken, err := store.Register("payments-api", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	output, code := runCLI(t, store, "rotate", "--id", clientID)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0. output:\n%s", code, output)
	}
	if strings.Contains(output, oldToken) {
		t.Errorf("rotate printed the superseded token:\n%s", output)
	}
	if !strings.Contains(output, "alog_"+clientID+"_rotated-"+clientID) {
		t.Errorf("rotate did not print the new token:\n%s", output)
	}
	if !strings.Contains(strings.ToLower(output), "not recoverable") {
		t.Errorf("output does not warn that the new token cannot be retrieved again:\n%s", output)
	}
}

func TestClientsRevoke(t *testing.T) {
	store := newMemoryClientStore()
	clientID, token, err := store.Register("payments-api", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	output, code := runCLI(t, store, "revoke", "--id", clientID)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0. output:\n%s", code, output)
	}
	if _, err := store.Authenticate(token); err == nil {
		t.Fatal("the token still authenticates after revoke")
	}

	// Revoking twice reports the failure rather than pretending to succeed.
	if _, code := runCLI(t, store, "revoke", "--id", clientID); code == 0 {
		t.Fatal("second revoke exited 0, want non-zero")
	}
}

func TestClientsUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no subcommand", args: nil},
		{name: "unknown subcommand", args: []string{"delete"}},
		{name: "rotate without id", args: []string{"rotate"}},
		{name: "revoke without id", args: []string{"revoke"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, code := runCLI(t, newMemoryClientStore(), tc.args...)
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero. output:\n%s", output)
			}
		})
	}
}

// TestRunClientsCommandUsageErrorsExitTwoWithoutTouchingTheDatabase covers
// runClientsCommand directly, not just runClientsCLI. Before this test,
// runClientsCommand had no coverage at all: it opened a database connection
// before looking at args, so a missing or unknown subcommand surfaced
// whatever loadConfig/db.Open/db.Ping produced (exit 1) instead of the usage
// exit 2 that runClientsCLI already returns for the same input. Usage
// errors must be indistinguishable from a database outage in exit code, in
// either direction, or a deployment script cannot branch on them.
func TestRunClientsCommandUsageErrorsExitTwoWithoutTouchingTheDatabase(t *testing.T) {
	tests := []struct {
		name        string
		databaseURL string
		args        []string
	}{
		{name: "no subcommand, DATABASE_URL unset", databaseURL: "", args: nil},
		{name: "unknown subcommand, DATABASE_URL unset", databaseURL: "", args: []string{"bogus"}},
		// A syntactically valid but unreachable DSN: if the usage check ran
		// after connecting, db.Ping would fail here and this would return 1.
		{name: "no subcommand, database unreachable", databaseURL: "postgres://audit:audit@127.0.0.1:1/audit?sslmode=disable", args: nil},
		{name: "unknown subcommand, database unreachable", databaseURL: "postgres://audit:audit@127.0.0.1:1/audit?sslmode=disable", args: []string{"bogus"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DATABASE_URL", tc.databaseURL)
			if code := runClientsCommand(tc.args); code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
		})
	}
}
