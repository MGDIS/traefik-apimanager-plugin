package traefik_apimanager_plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Config struct {
	APIManagerURL string   `json:"apiManagerURL,omitempty"`
	AuthMode      string   `json:"authMode,omitempty"`
	ClientID      string   `json:"clientID,omitempty"`
	ClientSecret  string   `json:"clientSecret,omitempty"`
	Username      string   `json:"username,omitempty"`
	Password      string   `json:"password,omitempty"`
	GrantType     string   `json:"grantType,omitempty"`
	HeaderName    string   `json:"headerName,omitempty"`
	HeaderValue   string   `json:"headerValue,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	Margin        int      `json:"margin,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type APIManagerPlugin struct {
	next          http.Handler
	name          string
	authMode      string
	apiManagerURL string
	clientID      string
	clientSecret  string
	username      string
	password      string
	grantType     string
	headerName    string
	headerValue   string
	paths         []string
	scope         string
	logger        *slog.Logger

	margin time.Duration

	mu          sync.RWMutex
	token       string
	tokenExpiry time.Time

	fetchMu sync.Mutex
}

type APIManagerQuery struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	GrantType string `json:"grant_type"`
	Scope     string `json:"scope"`
}

type APIManagerResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// defaultRefreshMargin is how far before real expiry a cached token is refreshed by
// default, so an about-to-expire token is never forwarded upstream. Operators may
// override it with the optional "margin" config (in seconds).
const defaultRefreshMargin = 30 * time.Second

// New - create a new instance of APIManagerPlugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// logger instance
	var logLevel slog.Leveler
	switch os.Getenv("TRAEFIK_API_MANAGER_PLUGIN_LOG_LEVEL") {
	case "DEBUG", "debug":
		logLevel = slog.LevelDebug
	case "INFO", "info":
		logLevel = slog.LevelInfo
	case "WARN", "warn":
		logLevel = slog.LevelWarn
	case "ERROR", "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	// if config.AuthMode is not set or different from "oauth2" or "apikey" log a message "no auth mode set or invalid auth mode"
	if config.AuthMode != "oauth2" && config.AuthMode != "apikey" {
		if config.AuthMode == "" {
			logger.Info("traefik-api-manager - empty auth mode")
		} else {
			logger.Error("traefik-api-manager - invalid auth mode")
		}
		logger.Info("traefik-api-manager - default auth mode used (required: oauth2 or apikey)")
	}

	// Refresh margin defaults to a fixed value; operators tune it only if they want.
	margin := defaultRefreshMargin
	if config.Margin > 0 {
		margin = time.Duration(config.Margin) * time.Second
	}

	return &APIManagerPlugin{
		next:          next,
		authMode:      config.AuthMode,
		apiManagerURL: config.APIManagerURL,
		clientID:      config.ClientID,
		clientSecret:  config.ClientSecret,
		scope:         config.Scope,
		username:      config.Username,
		password:      config.Password,
		grantType:     config.GrantType,
		headerName:    config.HeaderName,
		headerValue:   config.HeaderValue,
		paths:         config.Paths,
		name:          name,
		logger:        logger,
		margin:        margin,
	}, nil
}

// ServeHTTP - processes the request
func (a *APIManagerPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// If the request path does not match any regex, call the next handler in the chain
	if !a.checkPathMatching(req.URL.Path) {
		a.next.ServeHTTP(rw, req)
		return
	}

	a.logger.Info("traefik-api-manager - processing request", slog.String("method", req.Method), slog.String("path", req.URL.Path))

	switch a.authMode {
	case "oauth2":
		token, err := a.getToken()
		if err != nil {
			a.logger.Error("traefik-api-manager - failed to retrieve access token", slog.String("error", err.Error()))
			http.Error(rw, "Failed to retrieve access token", http.StatusInternalServerError)
			return
		}
		a.createXForwardedAuthHeader(req, fmt.Sprintf("Bearer %s", token))
	case "apikey":
		if strings.ToLower(a.headerName) == "authorization" {
			a.createXForwardedAuthHeader(req, a.headerValue)
		} else {
			req.Header.Set(a.headerName, a.headerValue)
		}
	default:
	}

	// Call the next handler in the chain
	a.next.ServeHTTP(rw, req)
}

// createXForwardedAuthHeader - Copy the current Authorization header to X-Forwarded-Authorization
func (a *APIManagerPlugin) createXForwardedAuthHeader(req *http.Request, value string) {
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		req.Header.Set("X-Forwarded-Authorization", authHeader)
	}
	req.Header.Set("Authorization", value)
}

// checkPathMatching - check if path is matching paths regexes
//
// Default case : if no paths are provided, return true
func (a *APIManagerPlugin) checkPathMatching(path string) bool {
	if len(a.paths) == 0 {
		return true
	}

	matched := false
	for _, pattern := range a.paths {
		matched, _ = regexp.MatchString(pattern, path)
		if matched {
			break
		}
	}

	return matched
}

// getToken - return the cached token, or fetch a fresh one when the cache is empty or
// expired. The expiry is now + expires_in - margin, so a
// missing expires_in (0) or a margin larger than the lifetime lands the expiry in the
// past and the next request simply refetches — no special-casing needed.
//
// mu guards the shared cache because Traefik serves requests on multiple goroutines in
// parallel. fetchMu coalesces refreshes: when the cache is stale, only one goroutine
// performs the upstream call while the rest wait, then re-read the freshly cached token
// instead of each firing its own request at the API manager.
func (a *APIManagerPlugin) getToken() (string, error) {
	if token, ok := a.cachedToken(); ok {
		return token, nil
	}

	a.fetchMu.Lock()
	defer a.fetchMu.Unlock()

	// Re-check: another goroutine may have refreshed the cache while we waited on fetchMu.
	if token, ok := a.cachedToken(); ok {
		return token, nil
	}

	token, expiresIn, err := a.getOAuth2AccessToken()
	if err != nil {
		return "", err
	}

	a.mu.Lock()
	a.token = token
	a.tokenExpiry = time.Now().Add(time.Duration(expiresIn)*time.Second - a.margin)
	a.mu.Unlock()
	return token, nil
}

// cachedToken - return the cached token and whether it is still valid (non-empty and
// not past its expiry). Guarded by mu for concurrent access.
func (a *APIManagerPlugin) cachedToken() (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.token, a.token != "" && time.Now().Before(a.tokenExpiry)
}

// getOAuth2AccessToken - call API manager with OAuth 2.0 protocol to get an access token
func (a *APIManagerPlugin) getOAuth2AccessToken() (string, int, error) {
	query := url.Values{}
	query.Set("grant_type", a.grantType)
	query.Set("username", a.username)
	query.Set("password", a.password)
	if a.scope != "" {
		query.Set("scope", a.scope)
	}

	requestBody := []byte(query.Encode())

	req, err := http.NewRequest("POST", a.apiManagerURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create POST request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", a.clientID, a.clientSecret)))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to send POST request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	if resp.StatusCode != http.StatusOK {
		a.logger.Debug("API manager returned an error",
			slog.String("plugin", "traefik-api-manager"),
			slog.String("username", a.username),
			slog.String("password", a.password),
			slog.String("grantType", a.grantType),
			slog.String("scope", a.scope),
			slog.String("clientID", a.clientID),
			slog.String("clientSecret", a.clientSecret),
			slog.String("url", a.apiManagerURL),
			slog.String("method", "POST"),
			slog.Any("headers", req.Header),
			slog.Int("statusCode", resp.StatusCode),
			slog.String("receivedBody", string(body)),
		)

		return "", 0, fmt.Errorf("API manager returned a %v status code", resp.StatusCode)
	}

	var apiResp APIManagerResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		a.logger.Debug("unable to parse JSON response from remote API manager",
			slog.String("plugin", "traefik-api-manager"),
			slog.String("username", a.username),
			slog.String("password", a.password),
			slog.String("grantType", a.grantType),
			slog.String("scope", a.scope),
			slog.String("clientID", a.clientID),
			slog.String("clientSecret", a.clientSecret),
			slog.String("url", a.apiManagerURL),
			slog.String("method", "POST"),
			slog.Any("headers", req.Header),
			slog.Int("statusCode", resp.StatusCode),
			slog.String("receivedBody", string(body)),
			slog.String("error", err.Error()),
		)

		return "", 0, err
	} else if apiResp.AccessToken == "" {
		a.logger.Debug("received access_token from API manager is a empty string",
			slog.String("plugin", "traefik-api-manager"),
			slog.String("username", a.username),
			slog.String("password", a.password),
			slog.String("grantType", a.grantType),
			slog.String("scope", a.scope),
			slog.String("clientID", a.clientID),
			slog.String("clientSecret", a.clientSecret),
			slog.String("url", a.apiManagerURL),
			slog.String("method", "POST"),
			slog.Any("headers", req.Header),
			slog.Int("statusCode", resp.StatusCode),
			slog.String("receivedBody", string(body)),
		)

		return "", 0, fmt.Errorf("parsed access_token is an empty string")
	}

	return apiResp.AccessToken, apiResp.ExpiresIn, nil
}
