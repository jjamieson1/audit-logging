package main

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type PostgresClientStore struct {
	db *sql.DB
}

func NewPostgresClientStore(db *sql.DB) (*PostgresClientStore, error) {
	if db == nil {
		return nil, errors.New("a database handle is required for the client registry")
	}

	store := &PostgresClientStore{db: db}
	if err := store.ensureSchema(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *PostgresClientStore) ensureSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS audit_clients (
    client_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'client',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
`)
	return err
}

func (s *PostgresClientStore) Authenticate(token string) (Principal, error) {
	clientID, secret, err := parseToken(token)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}

	var name, role, storedHash string
	var revokedAt sql.NullTime

	err = s.db.QueryRow(`
SELECT name, role, token_hash, revoked_at FROM audit_clients WHERE client_id = $1
`, clientID).Scan(&name, &role, &storedHash, &revokedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrUnauthorized
	}
	if err != nil {
		return Principal{}, err
	}
	if revokedAt.Valid {
		return Principal{}, ErrUnauthorized
	}

	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(storedHash)) != 1 {
		return Principal{}, ErrUnauthorized
	}

	return Principal{ClientID: clientID, Name: name, Role: role}, nil
}

func (s *PostgresClientStore) Register(name, role string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", errors.New("client name is required")
	}

	role = strings.TrimSpace(role)
	if role == "" {
		role = RoleClient
	}
	if !validRole(role) {
		return "", "", fmt.Errorf("invalid role %q: must be %q or %q", role, RoleClient, RoleAdmin)
	}

	clientID, err := newClientID()
	if err != nil {
		return "", "", err
	}
	secret, err := newSecret()
	if err != nil {
		return "", "", err
	}

	if _, err := s.db.Exec(`
INSERT INTO audit_clients(client_id, name, token_hash, role) VALUES ($1, $2, $3, $4)
`, clientID, name, hashSecret(secret), role); err != nil {
		return "", "", err
	}

	return clientID, formatToken(clientID, secret), nil
}

func (s *PostgresClientStore) Rotate(clientID string) (string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", errors.New("client id is required")
	}

	secret, err := newSecret()
	if err != nil {
		return "", err
	}

	// client_id is untouched, so entries already written stay attributed.
	result, err := s.db.Exec(`
UPDATE audit_clients SET token_hash = $1 WHERE client_id = $2 AND revoked_at IS NULL
`, hashSecret(secret), clientID)
	if err != nil {
		return "", err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected == 0 {
		return "", fmt.Errorf("no active client with id %q", clientID)
	}

	return formatToken(clientID, secret), nil
}

func (s *PostgresClientStore) Revoke(clientID string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return errors.New("client id is required")
	}

	// The row is kept so historical entries stay attributable to a named client.
	result, err := s.db.Exec(`
UPDATE audit_clients SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL
`, clientID)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("no active client with id %q", clientID)
	}

	return nil
}

func (s *PostgresClientStore) List() ([]ClientSummary, error) {
	rows, err := s.db.Query(`
SELECT client_id, name, role, created_at, revoked_at
FROM audit_clients
ORDER BY created_at ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summaries := make([]ClientSummary, 0)
	for rows.Next() {
		var summary ClientSummary
		var revokedAt sql.NullTime
		if err := rows.Scan(&summary.ClientID, &summary.Name, &summary.Role, &summary.CreatedAt, &revokedAt); err != nil {
			return nil, err
		}
		summary.Revoked = revokedAt.Valid
		summaries = append(summaries, summary)
	}

	return summaries, rows.Err()
}
