package traefik_apimanager_plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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
	// if config.AuthMode is not set or different from "oauth2" or "apikey" log a message "no auth mode set or invalid auth mode"
	if config.AuthMode != "oauth2" && config.AuthMode != "apikey" {
		if config.AuthMode == "" {
			log.Print("traefik-api-manager - empty auth mode")
		} else {
			log.Print("traefik-api-manager - invalid auth mode")
		}
		log.Print("traefik-api-manager - default auth mode used (required: oauth2 or apikey)")
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
	}, nil
}

// ServeHTTP - processes the request
func (a *APIManagerPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// If the request path does not match any regex, call the next handler in the chain
	if !a.checkPathMatching(req.URL.Path) {
		a.next.ServeHTTP(rw, req)
		return
	}

	log.Printf("traefik-api-manager - processing request: %s %s", req.Method, req.URL.Path)

	switch a.authMode {
	case "oauth2":
		token, err := a.getOAuth2AccessToken()
		if err != nil {
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
	query := APIManagerQuery{
		Username:  a.username,
		Password:  a.password,
		GrantType: a.grantType,
		Scope:     a.scope,
	}

	requestBody, err := json.Marshal(query)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest("POST", a.apiManagerURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create POST request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

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

	var apiResp APIManagerResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "", err
	}

	return apiResp.AccessToken, nil
}
