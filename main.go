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
}

type APIManagerQuery struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	GrantType string `json:"grant_type"`
	Scope     string `json:"scope"`
}

type APIManagerResponse struct {
	AccessToken string `json:"access_token"`
}

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
		token, err := a.getOAuth2AccessToken()
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

// getOAuth2AccessToken - call API manager with OAuth 2.0 protocol to get an access token
func (a *APIManagerPlugin) getOAuth2AccessToken() (string, error) {
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
		return "", fmt.Errorf("failed to create POST request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", a.clientID, a.clientSecret)))
	req.Header.Set("Authorization", "Basic "+auth)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send POST request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
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
			slog.Any("headers", map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Basic " + auth,
			}),
			slog.Int("statusCode", resp.StatusCode),
			slog.String("receivedBody", string(body)),
		)

		return "", fmt.Errorf("API manager returned a %v status code", resp.StatusCode)
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
			slog.Any("headers", map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Basic " + auth,
			}),
			slog.Int("statusCode", resp.StatusCode),
			slog.String("receivedBody", string(body)),
			slog.String("error", err.Error()),
		)

		return "", err
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
			slog.Any("headers", map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Basic " + auth,
			}),
			slog.Int("statusCode", resp.StatusCode),
			slog.String("receivedBody", string(body)),
		)

		return "", fmt.Errorf("parsed access_token is an empty string")
	}

	return apiResp.AccessToken, nil
}
