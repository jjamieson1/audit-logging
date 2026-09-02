package main

import (
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	clientID, err := newClientID()
	if err != nil {
		t.Fatalf("newClientID() error: %v", err)
	}
	secret, err := newSecret()
	if err != nil {
		t.Fatalf("newSecret() error: %v", err)
	}

	token := formatToken(clientID, secret)
	if !strings.HasPrefix(token, "alog_") {
		t.Fatalf("token %q does not start with the alog_ prefix", token)
	}

	gotID, gotSecret, err := parseToken(token)
	if err != nil {
		t.Fatalf("parseToken() error: %v", err)
	}
	if gotID != clientID {
		t.Errorf("clientID = %q, want %q", gotID, clientID)
	}
	if gotSecret != secret {
		t.Errorf("secret = %q, want %q", gotSecret, secret)
	}
}

func TestParseTokenHandlesUnderscoresInTheSecret(t *testing.T) {
	// The base64url alphabet includes "_", so a secret can legitimately
	// contain the separator. Splitting on every underscore would reject
	// perfectly valid tokens, intermittently and confusingly.
	const clientID = "a1b2c3d4e5f60718"
	const secret = "ab_cd__ef_"

	gotID, gotSecret, err := parseToken(formatToken(clientID, secret))
	if err != nil {
		t.Fatalf("parseToken() error: %v", err)
	}
	if gotID != clientID {
		t.Errorf("clientID = %q, want %q", gotID, clientID)
	}
	if gotSecret != secret {
		t.Errorf("secret = %q, want %q", gotSecret, secret)
	}
}

func TestParseTokenRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "no separators", in: "alog"},
		{name: "only one separator", in: "alog_a1b2c3d4e5f60718"},
		{name: "wrong prefix", in: "bearer_a1b2c3d4e5f60718_secret"},
		{name: "prefix case must match", in: "ALOG_a1b2c3d4e5f60718_secret"},
		{name: "empty client id", in: "alog__secret"},
		{name: "empty secret", in: "alog_a1b2c3d4e5f60718_"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseToken(tc.in); err == nil {
				t.Fatalf("parseToken(%q) succeeded, want error", tc.in)
			}
		})
	}
}

func TestGeneratedValuesAreDistinctAndSized(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		clientID, err := newClientID()
		if err != nil {
			t.Fatalf("newClientID() error: %v", err)
		}
		if len(clientID) != 16 {
			t.Fatalf("clientID %q has length %d, want 16 hex characters", clientID, len(clientID))
		}
		if strings.Contains(clientID, "_") {
			t.Fatalf("clientID %q contains the token separator", clientID)
		}
		if seen[clientID] {
			t.Fatalf("newClientID() repeated %q within 100 draws", clientID)
		}
		seen[clientID] = true

		secret, err := newSecret()
		if err != nil {
			t.Fatalf("newSecret() error: %v", err)
		}
		if len(secret) != 43 {
			t.Fatalf("secret has length %d, want 43 (32 bytes, base64url unpadded)", len(secret))
		}
	}
}

func TestHashSecretIsStableAndDistinguishing(t *testing.T) {
	if hashSecret("abc") != hashSecret("abc") {
		t.Fatal("hashSecret is not deterministic")
	}
	if hashSecret("abc") == hashSecret("abd") {
		t.Fatal("hashSecret collided on different inputs")
	}
	if strings.Contains(hashSecret("abc"), "abc") {
		t.Fatal("hashSecret leaked its input")
	}
}

func TestValidRole(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{role: "client", want: true},
		{role: "admin", want: true},
		{role: "Admin", want: false},
		{role: "root", want: false},
		{role: "", want: false},
	}

	for _, tc := range tests {
		if got := validRole(tc.role); got != tc.want {
			t.Errorf("validRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
}
