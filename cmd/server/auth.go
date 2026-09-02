package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
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

// contextKey is unexported so no other package can collide with it.
type contextKey struct{ name string }

var principalContextKey = &contextKey{name: "principal"}

// bearerToken pulls the credential out of an Authorization header. The scheme
// is compared case-insensitively; the token itself is not.
func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("authorization"))
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

func principalFrom(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey).(Principal)
	return principal, ok
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}

// requireAuth resolves the bearer token and puts the Principal in the request
// context. Every credential problem produces an identical 401, so the endpoint
// cannot be used to probe for valid client ids. A registry outage is a 503
// instead: it says nothing about the token, and reporting it as 401 would send
// operators hunting for a credential bug during a database incident.
func requireAuth(clients ClientStore, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeUnauthorized(w)
			return
		}

		principal, err := clients.Authenticate(token)
		if errors.Is(err, ErrUnauthorized) {
			writeUnauthorized(w)
			return
		}
		if err != nil {
			log.Printf("client registry unavailable: %v", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authentication unavailable"})
			return
		}

		handler(w, r.WithContext(context.WithValue(r.Context(), principalContextKey, principal)))
	}
}
