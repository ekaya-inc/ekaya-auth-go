package mcpoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	// ErrInvalidAuthURL indicates the requested auth_url was rejected by policy.
	ErrInvalidAuthURL = errors.New("invalid auth_url")
	// ErrAuthServerNotConfigured indicates no default auth server is configured.
	ErrAuthServerNotConfigured = errors.New("auth server not configured")
	// ErrInvalidProjectID indicates the resource path or project_id query value is invalid.
	ErrInvalidProjectID = errors.New("invalid project_id")
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// BaseURLResolver resolves the public base URL for resource metadata and local token endpoints.
type BaseURLResolver func(r *http.Request) (string, error)

// AuthURLResolver resolves the authorization server URL for discovery and token exchange.
type AuthURLResolver func(ctx context.Context, projectID string, requestedAuthURL string) (string, error)

// ProjectAuthLookup resolves a project-specific auth server URL when one exists.
type ProjectAuthLookup func(ctx context.Context, projectID string) (string, error)

// OAuthServerMetadata represents OAuth 2.0 Authorization Server Metadata (RFC 8414).
type OAuthServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	JWKSUri                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// ProtectedResourceMetadata represents OAuth 2.0 Protected Resource Metadata (RFC 9728).
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
}

// DCRRequest represents an OAuth 2.0 Dynamic Client Registration request (RFC 7591).
type DCRRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// DCRResponse represents an OAuth 2.0 Dynamic Client Registration response (RFC 7591).
type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
}

// TokenResponse represents a normalized OAuth token response body.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// Config defines the behavior of the shared MCP OAuth facade.
type Config struct {
	BaseURLResolver                      BaseURLResolver
	AuthURLResolver                      AuthURLResolver
	HTTPClient                           *http.Client
	SupportedScopes                      []string
	ClientID                             string
	AllowProjectIDQuery                  bool
	AllowAuthURLQuery                    bool
	StrictProjectID                      bool
	ProxyTokenResponse                   bool
	NormalizedTokenType                  string
	NormalizedExpiresIn                  int
	EchoRequestedTokenEndpointAuthMethod bool
}

// Handler implements the MCP-facing OAuth facade shared by engine/tunnel-like servers.
type Handler struct {
	baseURLResolver BaseURLResolver
	authURLResolver AuthURLResolver
	httpClient      *http.Client
	scopes          []string
	clientID        string

	allowProjectIDQuery bool
	allowAuthURLQuery   bool
	strictProjectID     bool

	proxyTokenResponse                   bool
	normalizedTokenType                  string
	normalizedExpiresIn                  int
	echoRequestedTokenEndpointAuthMethod bool
}

// New creates a shared MCP OAuth handler with explicit policy hooks.
func New(cfg Config) *Handler {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	scopes := cloneStrings(cfg.SupportedScopes)
	if len(scopes) == 0 {
		scopes = []string{"project:access"}
	}

	clientID := cfg.ClientID
	if clientID == "" {
		clientID = "ekaya-mcp"
	}

	tokenType := cfg.NormalizedTokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	return &Handler{
		baseURLResolver: cfg.BaseURLResolver,
		authURLResolver: cfg.AuthURLResolver,
		httpClient:      httpClient,
		scopes:          scopes,
		clientID:        clientID,

		allowProjectIDQuery: cfg.AllowProjectIDQuery,
		allowAuthURLQuery:   cfg.AllowAuthURLQuery,
		strictProjectID:     cfg.StrictProjectID,

		proxyTokenResponse:                   cfg.ProxyTokenResponse,
		normalizedTokenType:                  tokenType,
		normalizedExpiresIn:                  cfg.NormalizedExpiresIn,
		echoRequestedTokenEndpointAuthMethod: cfg.EchoRequestedTokenEndpointAuthMethod,
	}
}

// RegisterRoutes registers the shared MCP OAuth endpoints on a mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.OAuthDiscovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/{path...}", h.OAuthDiscovery)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", h.ProtectedResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{path...}", h.ProtectedResource)
	mux.HandleFunc("POST /mcp/oauth/token", h.TokenExchange)
	mux.HandleFunc("POST /mcp/{pid}/oauth/token", h.TokenExchange)
	mux.HandleFunc("POST /mcp/oauth/register", h.DynamicClientRegistration)
}

// OAuthDiscovery serves OAuth Authorization Server Metadata (RFC 8414).
func (h *Handler) OAuthDiscovery(w http.ResponseWriter, r *http.Request) {
	baseURL, err := h.baseURL(r)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build OAuth metadata")
		return
	}

	projectID, requestedAuthURL, isDynamic, err := h.discoveryInputs(r)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidProjectID):
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid project_id format")
		case errors.Is(err, ErrInvalidAuthURL):
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid auth_url: not in allowed list")
		default:
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build OAuth metadata")
		}
		return
	}

	authURL, err := h.resolveAuthURL(r.Context(), projectID, requestedAuthURL)
	if err != nil || authURL == "" {
		switch {
		case errors.Is(err, ErrInvalidAuthURL):
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid auth_url: not in allowed list")
		default:
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Authorization server not configured")
		}
		return
	}

	authorizationEndpoint, err := joinURL(authURL, "authorize")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build OAuth metadata")
		return
	}
	if projectID != "" {
		resource, err := joinURL(baseURL, "mcp", projectID)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build OAuth metadata")
			return
		}
		authEndpointURL, err := url.Parse(authorizationEndpoint)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build OAuth metadata")
			return
		}
		query := authEndpointURL.Query()
		query.Set("project_id", projectID)
		query.Set("resource", resource)
		authEndpointURL.RawQuery = query.Encode()
		authorizationEndpoint = authEndpointURL.String()
	}

	tokenPath := []string{"mcp", "oauth", "token"}
	if projectID != "" {
		tokenPath = []string{"mcp", projectID, "oauth", "token"}
	}
	tokenEndpoint, err := joinURL(baseURL, tokenPath...)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build OAuth metadata")
		return
	}

	registrationEndpoint, err := joinURL(baseURL, "mcp", "oauth", "register")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build OAuth metadata")
		return
	}

	jwksURI, err := joinURL(authURL, ".well-known", "jwks.json")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build OAuth metadata")
		return
	}

	metadata := OAuthServerMetadata{
		Issuer:                            authURL,
		AuthorizationEndpoint:             authorizationEndpoint,
		TokenEndpoint:                     tokenEndpoint,
		RegistrationEndpoint:              registrationEndpoint,
		JWKSUri:                           jwksURI,
		ScopesSupported:                   cloneStrings(h.scopes),
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
	}

	if isDynamic {
		w.Header().Set("Cache-Control", "private, no-cache")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	writeJSON(w, http.StatusOK, metadata)
}

// ProtectedResource serves OAuth Protected Resource Metadata (RFC 9728).
func (h *Handler) ProtectedResource(w http.ResponseWriter, r *http.Request) {
	authURL, err := h.resolveAuthURL(r.Context(), "", "")
	if err != nil || authURL == "" {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Authorization server not configured")
		return
	}

	baseURL, err := h.baseURL(r)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build resource metadata")
		return
	}

	path := strings.Trim(r.PathValue("path"), "/")
	projectID, err := h.parsePathProjectID(path)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid project_id format")
		return
	}

	resource := baseURL
	if path != "" {
		resource, err = joinURL(baseURL, path)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build resource metadata")
			return
		}
	}

	authorizationServer := baseURL
	if projectID != "" {
		authorizationServer = resource
	}

	metadata := ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   []string{authorizationServer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        cloneStrings(h.scopes),
	}

	if path == "" {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "private, no-cache")
	}
	writeJSON(w, http.StatusOK, metadata)
}

// TokenExchange exchanges an authorization code against the configured auth server.
func (h *Handler) TokenExchange(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request body")
		return
	}

	if grantType := r.FormValue("grant_type"); grantType != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Only authorization_code grant is supported")
		return
	}

	projectID := r.PathValue("pid")
	if projectID != "" {
		if err := h.validateProjectID(projectID); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid project_id format")
			return
		}
	}

	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	if code == "" || codeVerifier == "" || redirectURI == "" || clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing required parameters: code, redirect_uri, client_id, code_verifier")
		return
	}

	requestedAuthURL := r.FormValue("auth_url")
	authURL, err := h.resolveAuthURL(r.Context(), projectID, requestedAuthURL)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidAuthURL):
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid auth_url: not in allowed list")
		default:
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "Token exchange failed")
		}
		return
	}
	if authURL == "" {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Token exchange failed")
		return
	}

	reqBody, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"code_verifier": codeVerifier,
		"redirect_uri":  redirectURI,
		"client_id":     clientID,
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build token exchange request")
		return
	}

	tokenURL, err := joinURL(authURL, "token")
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build token exchange request")
		return
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, bytes.NewReader(reqBody))
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to build token exchange request")
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")

	upstreamResp, err := h.httpClient.Do(upstreamReq)
	if err != nil {
		writeOAuthError(w, http.StatusBadGateway, "server_error", "Token exchange failed")
		return
	}
	defer upstreamResp.Body.Close()

	body, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		writeOAuthError(w, http.StatusBadGateway, "server_error", "Token exchange failed")
		return
	}

	if h.proxyTokenResponse || upstreamResp.StatusCode != http.StatusOK {
		contentType := upstreamResp.Header.Get("Content-Type")
		if contentType == "" {
			contentType = "application/json"
		}
		w.Header().Set("Content-Type", contentType)
		setHeaderOrDefault(w.Header(), upstreamResp.Header, "Cache-Control", "no-store")
		setHeaderOrDefault(w.Header(), upstreamResp.Header, "Pragma", "no-cache")
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = w.Write(body)
		return
	}

	var upstreamToken TokenResponse
	if err := json.Unmarshal(body, &upstreamToken); err != nil || upstreamToken.AccessToken == "" {
		writeOAuthError(w, http.StatusBadGateway, "server_error", "Token exchange failed")
		return
	}

	tokenType := h.normalizedTokenType
	if tokenType == "" {
		tokenType = upstreamToken.TokenType
	}
	if tokenType == "" {
		tokenType = "Bearer"
	}

	expiresIn := h.normalizedExpiresIn
	if expiresIn == 0 {
		expiresIn = upstreamToken.ExpiresIn
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken: upstreamToken.AccessToken,
		TokenType:   tokenType,
		ExpiresIn:   expiresIn,
		Scope:       upstreamToken.Scope,
	})
}

// DynamicClientRegistration returns the public client metadata used by MCP/native clients.
func (h *Handler) DynamicClientRegistration(w http.ResponseWriter, r *http.Request) {
	var req DCRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "Invalid JSON request body")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	for _, redirectURI := range req.RedirectURIs {
		if errMsg := ValidateRedirectURI(redirectURI); errMsg != "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "Invalid redirect_uri: "+errMsg)
			return
		}
	}

	tokenEndpointAuthMethod := "none"
	if h.echoRequestedTokenEndpointAuthMethod && req.TokenEndpointAuthMethod != "" {
		tokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	scope := req.Scope
	if scope == "" && len(h.scopes) > 0 {
		scope = h.scopes[0]
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, DCRResponse{
		ClientID:                h.clientID,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		RedirectURIs:            cloneStrings(req.RedirectURIs),
		ClientName:              req.ClientName,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		GrantTypes:              cloneStrings(grantTypes),
		ResponseTypes:           cloneStrings(responseTypes),
		Scope:                   scope,
	})
}

// StaticBaseURLResolver returns a resolver that always uses the configured public base URL.
func StaticBaseURLResolver(baseURL string) BaseURLResolver {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return func(_ *http.Request) (string, error) {
		return trimmed, nil
	}
}

// RequestBaseURLResolver derives the base URL from the current request.
func RequestBaseURLResolver(r *http.Request) (string, error) {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	u := &url.URL{
		Scheme: scheme,
		Host:   r.Host,
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// AllowlistAuthURLResolver returns a resolver with a default auth server and optional allowed alternatives.
func AllowlistAuthURLResolver(defaultAuthURL string, allowed map[string]struct{}) AuthURLResolver {
	return LookupAuthURLResolver(defaultAuthURL, allowed, nil)
}

// LookupAuthURLResolver returns a resolver that optionally looks up a project-specific
// auth server URL and validates all returned URLs against the same allowlist.
func LookupAuthURLResolver(defaultAuthURL string, allowed map[string]struct{}, lookup ProjectAuthLookup) AuthURLResolver {
	defaultAuthURL = strings.TrimRight(strings.TrimSpace(defaultAuthURL), "/")
	normalizedAllowed := make(map[string]struct{}, len(allowed))
	for issuer := range allowed {
		normalizedAllowed[strings.TrimRight(strings.TrimSpace(issuer), "/")] = struct{}{}
	}

	validate := func(raw string) (string, error) {
		authURL := strings.TrimRight(strings.TrimSpace(raw), "/")
		if authURL == "" {
			if defaultAuthURL == "" {
				return "", ErrAuthServerNotConfigured
			}
			return defaultAuthURL, nil
		}
		if authURL == defaultAuthURL {
			return authURL, nil
		}
		if _, ok := normalizedAllowed[authURL]; ok {
			return authURL, nil
		}
		return "", ErrInvalidAuthURL
	}

	return func(ctx context.Context, projectID string, requestedAuthURL string) (string, error) {
		if requestedAuthURL != "" {
			return validate(requestedAuthURL)
		}

		if projectID != "" && lookup != nil {
			if lookedUpAuthURL, err := lookup(ctx, projectID); err == nil && lookedUpAuthURL != "" {
				return validate(lookedUpAuthURL)
			}
		}

		return validate("")
	}
}

// ValidateRedirectURI validates a redirect URI for native/public client registration.
func ValidateRedirectURI(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "malformed URI"
	}
	if parsed.Scheme == "" {
		return "missing scheme"
	}
	if parsed.Host == "" {
		return "missing host"
	}

	host := parsed.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return ""
	}
	if parsed.Scheme != "https" {
		return "non-localhost URIs must use HTTPS"
	}
	return ""
}

func (h *Handler) discoveryInputs(r *http.Request) (string, string, bool, error) {
	var projectID string
	isDynamic := false

	if h.allowProjectIDQuery {
		projectID = strings.TrimSpace(r.URL.Query().Get("project_id"))
		if projectID != "" {
			if err := h.validateProjectID(projectID); err != nil {
				return "", "", false, err
			}
			isDynamic = true
		}
	}

	if projectID == "" {
		pathProjectID, err := h.parsePathProjectID(strings.Trim(r.PathValue("path"), "/"))
		if err != nil {
			return "", "", false, err
		}
		if pathProjectID != "" {
			projectID = pathProjectID
			isDynamic = true
		}
	}

	requestedAuthURL := ""
	if h.allowAuthURLQuery {
		requestedAuthURL = strings.TrimSpace(r.URL.Query().Get("auth_url"))
		if requestedAuthURL != "" {
			isDynamic = true
		}
	}

	return projectID, requestedAuthURL, isDynamic, nil
}

func (h *Handler) parsePathProjectID(path string) (string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return "", nil
	}

	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] != "mcp" {
		return "", nil
	}
	if parts[1] == "" {
		return "", ErrInvalidProjectID
	}
	if err := h.validateProjectID(parts[1]); err != nil {
		return "", err
	}
	return parts[1], nil
}

func (h *Handler) validateProjectID(projectID string) error {
	if projectID == "" {
		return ErrInvalidProjectID
	}
	if !h.strictProjectID {
		return nil
	}
	if !uuidPattern.MatchString(projectID) {
		return ErrInvalidProjectID
	}
	return nil
}

func (h *Handler) baseURL(r *http.Request) (string, error) {
	if h.baseURLResolver == nil {
		return "", ErrAuthServerNotConfigured
	}
	baseURL, err := h.baseURLResolver(r)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(strings.TrimSpace(baseURL), "/"), nil
}

func (h *Handler) resolveAuthURL(ctx context.Context, projectID string, requestedAuthURL string) (string, error) {
	if h.authURLResolver == nil {
		return "", ErrAuthServerNotConfigured
	}
	authURL, err := h.authURLResolver(ctx, projectID, requestedAuthURL)
	return strings.TrimRight(strings.TrimSpace(authURL), "/"), err
}

func joinURL(base string, elems ...string) (string, error) {
	return url.JoinPath(base, elems...)
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func setHeaderOrDefault(dst, src http.Header, key, fallback string) {
	if value := src.Get(key); value != "" {
		dst.Set(key, value)
		return
	}
	dst.Set(key, fallback)
}
