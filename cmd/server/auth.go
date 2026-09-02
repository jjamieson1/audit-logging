package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	RoleClient = "client"
	RoleAdmin  = "admin"
)

const (
	tokenPrefix    = "alog"
	tokenSeparator = "_"
	clientIDBytes  = 8  // 16 hex characters
	secretBytes    = 32 // 43 base64url characters
)

// ErrUnauthorized is the single failure returned for every authentication
// problem. Missing, malformed, unknown and revoked tokens must be
// indistinguishable so the endpoint cannot be used to probe for valid IDs.
var ErrUnauthorized = errors.New("unauthorized")

// Principal is the authenticated caller behind a request.
type Principal struct {
	ClientID string
	Name     string
	Role     string
}

func (p Principal) IsAdmin() bool { return p.Role == RoleAdmin }

// ClientSummary is the operator-facing view of a client. It deliberately
// carries no token and no hash.
type ClientSummary struct {
	ClientID  string
	Name      string
	Role      string
	CreatedAt time.Time
	Revoked   bool
}

type ClientStore interface {
	// Authenticate resolves a presented token, returning ErrUnauthorized for
	// any failure a caller is allowed to learn about.
	Authenticate(token string) (Principal, error)
	// Register creates a client and returns its id and its full token. The
	// token is the only time the secret exists outside the caller's hands.
	Register(name, role string) (clientID string, token string, err error)
	// Rotate issues a new secret for an existing client, keeping its id so
	// entries it has already written stay attributed to it.
	Rotate(clientID string) (token string, err error)
	Revoke(clientID string) error
	List() ([]ClientSummary, error)
}

func validRole(role string) bool {
	return role == RoleClient || role == RoleAdmin
}

func newClientID() (string, error) {
	buf := make([]byte, clientIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func newSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func formatToken(clientID, secret string) string {
	return tokenPrefix + tokenSeparator + clientID + tokenSeparator + secret
}

// parseToken splits a token into its client id and secret.
//
// It splits on the FIRST TWO separators only. The base64url alphabet includes
// "_", so a secret may contain separators of its own; splitting on all of them
// would reject valid tokens whenever a random secret happened to include one.
func parseToken(token string) (string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(token), tokenSeparator, 3)
	if len(parts) != 3 || parts[0] != tokenPrefix || parts[1] == "" || parts[2] == "" {
		return "", "", ErrUnauthorized
	}
	return parts[1], parts[2], nil
}

func hashSecret(secret string) string {
	return sha256Hex([]byte(secret))
}
