package mcpoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testProjectID = "6089f231-1234-5678-9abc-def012345678"

func newTestHandler(cfg Config) *Handler {
	if cfg.BaseURLResolver == nil {
		cfg.BaseURLResolver = StaticBaseURLResolver("https://mcp.ekaya.ai")
	}
	if cfg.AuthURLResolver == nil {
		cfg.AuthURLResolver = AllowlistAuthURLResolver("https://auth.ekaya.ai", map[string]struct{}{
			"https://auth.ekaya.ai": {},
		})
	}
	cfg.StrictProjectID = true
	return New(cfg)
}

func TestOAuthDiscovery_ProjectScopedStatic(t *testing.T) {
	handler := newTestHandler(Config{})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server/mcp/"+testProjectID, nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-cache" {
		t.Fatalf("Cache-Control = %q, want %q", got, "private, no-cache")
	}

	var metadata OAuthServerMetadata
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode: %v", err)
	}

	authEndpoint, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		t.Fatalf("parse authorization endpoint: %v", err)
	}
	if authEndpoint.Scheme != "https" || authEndpoint.Host != "auth.ekaya.ai" || authEndpoint.Path != "/authorize" {
		t.Fatalf("authorization_endpoint = %q", metadata.AuthorizationEndpoint)
	}
	if got := authEndpoint.Query().Get("project_id"); got != testProjectID {
		t.Fatalf("project_id query = %q, want %q", got, testProjectID)
	}
	if got := authEndpoint.Query().Get("resource"); got != "https://mcp.ekaya.ai/mcp/"+testProjectID {
		t.Fatalf("resource query = %q", got)
	}
	if metadata.TokenEndpoint != "https://mcp.ekaya.ai/mcp/"+testProjectID+"/oauth/token" {
		t.Fatalf("token_endpoint = %q", metadata.TokenEndpoint)
	}
	if metadata.RegistrationEndpoint != "https://mcp.ekaya.ai/mcp/oauth/register" {
		t.Fatalf("registration_endpoint = %q", metadata.RegistrationEndpoint)
	}
	if metadata.JWKSUri != "https://auth.ekaya.ai/.well-known/jwks.json" {
		t.Fatalf("jwks_uri = %q", metadata.JWKSUri)
	}
}

func TestOAuthDiscovery_ProjectSpecificLookup(t *testing.T) {
	handler := newTestHandler(Config{
		AllowProjectIDQuery: true,
		AllowAuthURLQuery:   true,
		AuthURLResolver: LookupAuthURLResolver("https://auth.ekaya.ai", map[string]struct{}{
			"https://auth.ekaya.ai":     {},
			"https://auth.dev.ekaya.ai": {},
		}, func(_ctx context.Context, projectID string) (string, error) {
			if projectID == testProjectID {
				return "https://auth.dev.ekaya.ai", nil
			}
			return "", nil
		}),
	})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server?project_id="+testProjectID, nil)
	rec := httptest.NewRecorder()

	handler.OAuthDiscovery(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var metadata OAuthServerMetadata
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if metadata.Issuer != "https://auth.dev.ekaya.ai" {
		t.Fatalf("issuer = %q, want %q", metadata.Issuer, "https://auth.dev.ekaya.ai")
	}
}

func TestProtectedResource_BaseEndpoint(t *testing.T) {
	handler := newTestHandler(Config{})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ProtectedResource(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("Cache-Control = %q, want %q", got, "public, max-age=3600")
	}

	var metadata ProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if metadata.Resource != "https://mcp.ekaya.ai" {
		t.Fatalf("resource = %q", metadata.Resource)
	}
	if len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://mcp.ekaya.ai" {
		t.Fatalf("authorization_servers = %v", metadata.AuthorizationServers)
	}
}

func TestOAuthDiscovery_InvalidProjectPath(t *testing.T) {
	handler := newTestHandler(Config{})
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server/mcp/not-a-uuid", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestTokenExchange_ProxyResponse(t *testing.T) {
	var received map[string]string

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			t.Fatalf("path = %q, want %q", r.URL.Path, "/token")
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "proxy-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	t.Cleanup(authServer.Close)

	handler := newTestHandler(Config{
		AuthURLResolver:    AllowlistAuthURLResolver(authServer.URL, map[string]struct{}{authServer.URL: {}}),
		ProxyTokenResponse: true,
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"auth-code"},
		"code_verifier": {"pkce-verifier"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"ekaya-mcp"},
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp/"+testProjectID+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("pid", testProjectID)
	rec := httptest.NewRecorder()

	handler.TokenExchange(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if received["code"] != "auth-code" || received["code_verifier"] != "pkce-verifier" || received["client_id"] != "ekaya-mcp" {
		t.Fatalf("unexpected upstream body: %#v", received)
	}

	var response TokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.AccessToken != "proxy-token" || response.ExpiresIn != 3600 {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestTokenExchange_NormalizedResponse(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "normalized-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	t.Cleanup(authServer.Close)

	handler := newTestHandler(Config{
		AuthURLResolver:     AllowlistAuthURLResolver(authServer.URL, map[string]struct{}{authServer.URL: {}}),
		ProxyTokenResponse:  false,
		NormalizedExpiresIn: 86400,
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"auth-code"},
		"code_verifier": {"pkce-verifier"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"client_id":     {"ekaya-mcp"},
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.TokenExchange(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var response TokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.AccessToken != "normalized-token" {
		t.Fatalf("access_token = %q", response.AccessToken)
	}
	if response.ExpiresIn != 86400 {
		t.Fatalf("expires_in = %d, want %d", response.ExpiresIn, 86400)
	}
}

func TestDynamicClientRegistration_DefaultsToPublicClient(t *testing.T) {
	handler := newTestHandler(Config{})
	req := httptest.NewRequest(http.MethodPost, "/mcp/oauth/register", strings.NewReader(`{"redirect_uris":["http://localhost:3000/callback"]}`))
	rec := httptest.NewRecorder()

	handler.DynamicClientRegistration(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	var response DCRResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.ClientID != "ekaya-mcp" {
		t.Fatalf("client_id = %q", response.ClientID)
	}
	if response.TokenEndpointAuthMethod != "none" {
		t.Fatalf("token_endpoint_auth_method = %q", response.TokenEndpointAuthMethod)
	}
	if response.Scope != "project:access" {
		t.Fatalf("scope = %q", response.Scope)
	}
}

func TestDynamicClientRegistration_EchoesRequestedMethod(t *testing.T) {
	handler := newTestHandler(Config{
		EchoRequestedTokenEndpointAuthMethod: true,
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp/oauth/register", strings.NewReader(`{"redirect_uris":["http://localhost:3000/callback"],"token_endpoint_auth_method":"client_secret_post"}`))
	rec := httptest.NewRecorder()

	handler.DynamicClientRegistration(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	var response DCRResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.TokenEndpointAuthMethod != "client_secret_post" {
		t.Fatalf("token_endpoint_auth_method = %q", response.TokenEndpointAuthMethod)
	}
}
