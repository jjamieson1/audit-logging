package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// fakeClientStore resolves tokens from a map so handler tests need no database.
type fakeClientStore struct {
	byToken map[string]Principal
	failure error
}

func (f *fakeClientStore) Authenticate(token string) (Principal, error) {
	if f.failure != nil {
		return Principal{}, f.failure
	}
	principal, ok := f.byToken[token]
	if !ok {
		return Principal{}, ErrUnauthorized
	}
	return principal, nil
}

func (f *fakeClientStore) Register(string, string) (string, string, error) {
	return "", "", errors.New("not implemented in the fake")
}
func (f *fakeClientStore) Rotate(string) (string, error) {
	return "", errors.New("not implemented in the fake")
}
func (f *fakeClientStore) Revoke(string) error {
	return errors.New("not implemented in the fake")
}
func (f *fakeClientStore) List() ([]ClientSummary, error) {
	return nil, errors.New("not implemented in the fake")
}

const (
	tokenAlpha  = "alog_1111111111111111_alpha-secret"
	tokenBeta   = "alog_2222222222222222_beta-secret"
	tokenAdmin  = "alog_3333333333333333_admin-secret"
	clientAlpha = "1111111111111111"
	clientBeta  = "2222222222222222"
)

func newTestServer(t *testing.T) (*httptest.Server, *FileStore, *fakeClientStore) {
	t.Helper()

	store, err := NewFileStore(filepath.Join(t.TempDir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("NewFileStore() error: %v", err)
	}

	clients := &fakeClientStore{byToken: map[string]Principal{
		tokenAlpha: {ClientID: clientAlpha, Name: "alpha", Role: RoleClient},
		tokenBeta:  {ClientID: clientBeta, Name: "beta", Role: RoleClient},
		tokenAdmin: {ClientID: "3333333333333333", Name: "ops", Role: RoleAdmin},
	}}

	cfg := Config{MaxPayloadBytes: 32768, Query: defaultQueryLimits()}
	server := httptest.NewServer(newRouter(cfg, store, clients))
	t.Cleanup(server.Close)

	return server, store, clients
}

// do issues a request against the test server, setting a bearer token when one
// is given.
func do(t *testing.T, server *httptest.Server, method, path, token, body string) *http.Response {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	req.Header.Set("content-type", "application/json")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	return resp
}

func decodeResult(t *testing.T, resp *http.Response) LogQueryResult {
	t.Helper()

	var result LogQueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return result
}

func TestHealthNeedsNoToken(t *testing.T) {
	server, _, _ := newTestServer(t)

	resp := do(t, server, http.MethodGet, "/v1/health", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestLogEndpointsRejectMissingAndBadTokens(t *testing.T) {
	server, _, _ := newTestServer(t)

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/v1/logs", body: `{"app":"a","level":"INFO","message":"m"}`},
		{method: http.MethodGet, path: "/v1/logs"},
		{method: http.MethodGet, path: "/v1/logs/search?q=x"},
		{method: http.MethodGet, path: "/v1/verify"},
	}

	credentials := []struct {
		name  string
		token string
	}{
		{name: "no token", token: ""},
		{name: "unknown token", token: "alog_9999999999999999_nope"},
		{name: "malformed token", token: "garbage"},
	}

	for _, endpoint := range endpoints {
		for _, credential := range credentials {
			t.Run(endpoint.method+" "+endpoint.path+" with "+credential.name, func(t *testing.T) {
				resp := do(t, server, endpoint.method, endpoint.path, credential.token, endpoint.body)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
				}
				if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
					t.Errorf("WWW-Authenticate = %q, want %q", got, "Bearer")
				}

				var payload map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
					t.Fatalf("decoding body: %v", err)
				}
				// Identical for every failure, so the endpoint is not an oracle.
				if payload["error"] != "unauthorized" {
					t.Errorf("error = %q, want %q", payload["error"], "unauthorized")
				}
			})
		}
	}
}

func TestWrongAuthSchemeIsRejected(t *testing.T) {
	server, _, _ := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/logs", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	req.Header.Set("authorization", "Basic "+tokenAlpha)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	server, _, _ := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/logs", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	req.Header.Set("authorization", "bEaReR "+tokenAlpha)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestValidTokenReachesTheHandlers(t *testing.T) {
	server, _, _ := newTestServer(t)

	resp := do(t, server, http.MethodPost, "/v1/logs", tokenAlpha, `{"app":"payments","level":"INFO","message":"ok"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("write status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	resp = do(t, server, http.MethodGet, "/v1/verify", tokenAlpha, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestRegistryOutageIsNotReportedAsUnauthorized(t *testing.T) {
	server, _, clients := newTestServer(t)
	clients.failure = errors.New("connection refused")

	resp := do(t, server, http.MethodGet, "/v1/logs", tokenAlpha, "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// seedTwoClientsAndLegacy writes entries for alpha, for beta, and one
// unattributed entry of the kind that existed before authorization.
func seedTwoClientsAndLegacy(t *testing.T, store *FileStore) {
	t.Helper()

	records := []LogRecord{
		{App: "legacy-app", Level: "INFO", Message: "written before auth existed"},
		{ClientID: clientAlpha, App: "payments", Level: "INFO", Message: "alpha one"},
		{ClientID: clientBeta, App: "billing", Level: "ERROR", Message: "beta one"},
		{ClientID: clientAlpha, App: "payments", Level: "ERROR", Message: "alpha two"},
		{ClientID: clientBeta, App: "billing", Level: "INFO", Message: "beta two"},
	}

	for _, record := range records {
		if _, err := store.Append(record); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}
}

func TestWriteStampsTheAuthenticatedClient(t *testing.T) {
	server, store, _ := newTestServer(t)

	resp := do(t, server, http.MethodPost, "/v1/logs", tokenAlpha, `{"app":"payments","level":"INFO","message":"stamped"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	result, err := store.QueryLogs(LogQuery{Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("stored %d entries, want 1", len(result.Items))
	}
	if got := result.Items[0].Record.ClientID; got != clientAlpha {
		t.Fatalf("stored clientId = %q, want %q", got, clientAlpha)
	}
}

func TestWriteOverwritesCallerSuppliedClientID(t *testing.T) {
	server, store, _ := newTestServer(t)

	// Alpha's token, but the body claims to be beta.
	body := `{"clientId":"` + clientBeta + `","app":"payments","level":"INFO","message":"forged"}`
	resp := do(t, server, http.MethodPost, "/v1/logs", tokenAlpha, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	result, err := store.QueryLogs(LogQuery{Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if got := result.Items[0].Record.ClientID; got != clientAlpha {
		t.Fatalf("stored clientId = %q, want %q — attribution was forgeable", got, clientAlpha)
	}
}

func TestReadsAreScopedToTheCallersClient(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	resp := do(t, server, http.MethodGet, "/v1/logs?limit=50", tokenAlpha, "")
	result := decodeResult(t, resp)

	if len(result.Items) != 2 {
		t.Fatalf("alpha saw %d entries, want 2", len(result.Items))
	}
	for _, item := range result.Items {
		if item.Record.ClientID != clientAlpha {
			t.Fatalf("alpha saw an entry belonging to %q", item.Record.ClientID)
		}
	}
}

func TestSearchIsScopedToTheCallersClient(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	// "one" matches both "alpha one" and "beta one".
	resp := do(t, server, http.MethodGet, "/v1/logs/search?q=one&limit=50", tokenAlpha, "")
	result := decodeResult(t, resp)

	if len(result.Items) != 1 {
		t.Fatalf("search returned %d entries, want 1", len(result.Items))
	}
	if result.Items[0].Record.ClientID != clientAlpha {
		t.Fatal("free-text search reached across clients")
	}
}

func TestNonAdminCannotWidenScopeWithClientIDParam(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	// Alpha asks for beta's entries. The parameter is ignored, not honoured,
	// and not an error.
	resp := do(t, server, http.MethodGet, "/v1/logs?limit=50&clientId="+clientBeta, tokenAlpha, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	result := decodeResult(t, resp)
	if len(result.Items) != 2 {
		t.Fatalf("returned %d entries, want alpha's 2", len(result.Items))
	}
	for _, item := range result.Items {
		if item.Record.ClientID != clientAlpha {
			t.Fatalf("clientId parameter widened scope to %q", item.Record.ClientID)
		}
	}
}

func TestAdminReadsEverythingIncludingLegacyEntries(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	resp := do(t, server, http.MethodGet, "/v1/logs?limit=50", tokenAdmin, "")
	result := decodeResult(t, resp)

	if len(result.Items) != 5 {
		t.Fatalf("admin saw %d entries, want all 5", len(result.Items))
	}

	var legacy int
	for _, item := range result.Items {
		if item.Record.ClientID == "" {
			legacy++
		}
	}
	if legacy != 1 {
		t.Fatalf("admin saw %d unattributed entries, want 1", legacy)
	}
}

func TestAdminCanScopeToOneClient(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	resp := do(t, server, http.MethodGet, "/v1/logs?limit=50&clientId="+clientBeta, tokenAdmin, "")
	result := decodeResult(t, resp)

	if len(result.Items) != 2 {
		t.Fatalf("admin scoped read returned %d entries, want 2", len(result.Items))
	}
	for _, item := range result.Items {
		if item.Record.ClientID != clientBeta {
			t.Fatalf("scoped read returned an entry for %q", item.Record.ClientID)
		}
	}
}

func TestScopedPaginationDoesNotLeakAcrossClients(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	// A page size of 1 forces a cursor walk through interleaved owners.
	seen := 0
	path := "/v1/logs?limit=1"
	for page := 0; page < 10; page++ {
		resp := do(t, server, http.MethodGet, path, tokenBeta, "")
		result := decodeResult(t, resp)

		for _, item := range result.Items {
			if item.Record.ClientID != clientBeta {
				t.Fatalf("page %d leaked an entry belonging to %q", page, item.Record.ClientID)
			}
			seen++
		}
		if result.NextCursor == nil {
			break
		}
		path = "/v1/logs?limit=1&cursor=" + *result.NextCursor
	}

	if seen != 2 {
		t.Fatalf("cursor walk saw %d of beta's entries, want 2", seen)
	}
}
