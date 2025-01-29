package traefik_apimanager_plugin_test

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	apimanager "github.com/MGDIS/traefik-apimanager-plugin"
)

type logCapture struct {
	buf bytes.Buffer
}

func (lc *logCapture) Write(p []byte) (n int, err error) {
	return lc.buf.Write(p)
}

func (lc *logCapture) String() string {
	return lc.buf.String()
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("expected header value %s, but got %s", expected, req.Header.Get(key))
	}
}

func TestEmptyAuthModeLog(t *testing.T) {
	// Capture log output
	lc := &logCapture{}
	log.SetOutput(lc)

	cfg := apimanager.CreateConfig()
	cfg.AuthMode = ""

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	logOutput := lc.String()
	expectedMessage := "traefik-api-manager - empty auth mode"
	if !bytes.Contains([]byte(logOutput), []byte(expectedMessage)) {
		t.Errorf("expected log message %q, but got %q", expectedMessage, logOutput)
	}
}

func TestInvalidAuthModeLog(t *testing.T) {
	// Capture log output
	lc := &logCapture{}
	log.SetOutput(lc)

	cfg := apimanager.CreateConfig()
	cfg.AuthMode = "wrong"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	logOutput := lc.String()
	expectedMessage := "traefik-api-manager - invalid auth mode"
	if !bytes.Contains([]byte(logOutput), []byte(expectedMessage)) {
		t.Errorf("expected log message %q, but got %q", expectedMessage, logOutput)
	}
}

func TestAPIManagerPluginDefault(t *testing.T) {
	// Create a mock server that simulate api manager response
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token"}`)); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	cfg := apimanager.CreateConfig()
	cfg.APIManagerURL = mockServer.URL
	cfg.ClientID = "clientID"
	cfg.ClientSecret = "clientSecret"
	cfg.Username = "user"
	cfg.Password = "pass"
	cfg.GrantType = "password"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add Authorization header to the request
	req.Header.Set("Authorization", "Bearer awesome_token")

	handler.ServeHTTP(recorder, req)
	assertHeader(t, req, "Authorization", "Bearer awesome_token")
}

func TestAPIManagerPluginOAuth2(t *testing.T) {
	// Create a mock server that simulate api manager response
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token"}`)); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	cfg := apimanager.CreateConfig()
	cfg.APIManagerURL = mockServer.URL
	cfg.AuthMode = "oauth2"
	cfg.ClientID = "clientID"
	cfg.ClientSecret = "clientSecret"
	cfg.Username = "user"
	cfg.Password = "pass"
	cfg.GrantType = "password"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add Authorization header to the request
	req.Header.Set("Authorization", "Bearer awesome_token")

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-Forwarded-Authorization", "Bearer awesome_token")
	assertHeader(t, req, "Authorization", "Bearer apimanager_token")
}

func TestAPIManagerPluginOAuth2APIMErr(t *testing.T) {
	// Create a mock server that simulate api manager response
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNotFound)
	}))
	defer mockServer.Close()

	cfg := apimanager.CreateConfig()
	cfg.APIManagerURL = mockServer.URL
	cfg.AuthMode = "oauth2"
	cfg.ClientID = "clientID"
	cfg.ClientSecret = "clientSecret"
	cfg.Username = "user"
	cfg.Password = "pass"
	cfg.GrantType = "password"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add Authorization header to the request
	req.Header.Set("Authorization", "Bearer awesome_token")

	handler.ServeHTTP(recorder, req)

	// test http error code 500
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("invalid status code: %d", recorder.Code)
	}

	// test error message
	if recorder.Body.String() != "Failed to retrieve access token\n" {
		t.Errorf("invalid error message: %s", recorder.Body.String())
	}

	assertHeader(t, req, "Authorization", "Bearer awesome_token")
}

func TestAPIManagerPluginAPIKey(t *testing.T) {
	// Create a mock server that simulate api manager response
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token"}`)); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	cfg := apimanager.CreateConfig()
	cfg.APIManagerURL = mockServer.URL
	cfg.AuthMode = "apikey"
	cfg.HeaderName = "X-API-KEY"
	cfg.HeaderValue = "5w0fA6VL4WDRGR9aHKphMgunRoYN2Q6v"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add Authorization header to the request
	req.Header.Set("Authorization", "Bearer awesome_token")

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-API-KEY", "5w0fA6VL4WDRGR9aHKphMgunRoYN2Q6v")
	assertHeader(t, req, "Authorization", "Bearer awesome_token")
}

func TestAPIManagerPluginAPIKeyXForwarded(t *testing.T) {
	// Create a mock server that simulate api manager response
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token"}`)); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	cfg := apimanager.CreateConfig()
	cfg.APIManagerURL = mockServer.URL
	cfg.AuthMode = "apikey"
	cfg.HeaderName = "Authorization"
	cfg.HeaderValue = "5w0fA6VL4WDRGR9aHKphMgunRoYN2Q6v"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add Authorization header to the request
	req.Header.Set("Authorization", "Bearer awesome_token")

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-Forwarded-Authorization", "Bearer awesome_token")
	assertHeader(t, req, "Authorization", "5w0fA6VL4WDRGR9aHKphMgunRoYN2Q6v")
}

func TestAPIManagerPluginWithPaths(t *testing.T) {
	// Create a mock server that simulate api manager response
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token"}`)); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	cfg := apimanager.CreateConfig()
	cfg.APIManagerURL = mockServer.URL
	cfg.AuthMode = "oauth2"
	cfg.ClientID = "clientID"
	cfg.ClientSecret = "clientSecret"
	cfg.Username = "user"
	cfg.Password = "pass"
	cfg.GrantType = "password"
	cfg.Paths = []string{"^/demo$", "^/demo/.+$", "^/foobar/.*$"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/demo", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add Authorization header to the request
	req.Header.Set("Authorization", "Bearer awesome_token")

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "X-Forwarded-Authorization", "Bearer awesome_token")
	assertHeader(t, req, "Authorization", "Bearer apimanager_token")
}

func TestAPIManagerPluginDontTriggerPaths(t *testing.T) {
	// Create a mock server that simulate api manager response
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token"}`)); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	cfg := apimanager.CreateConfig()
	cfg.APIManagerURL = mockServer.URL
	cfg.ClientID = "clientID"
	cfg.ClientSecret = "clientSecret"
	cfg.Username = "user"
	cfg.Password = "pass"
	cfg.GrantType = "password"
	cfg.Paths = []string{"^/demo$", "^/demo/.+$", "^/foobar/.*$"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/foo", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add Authorization header to the request
	req.Header.Set("Authorization", "Bearer awesome_token")

	handler.ServeHTTP(recorder, req)

	assertHeader(t, req, "Authorization", "Bearer awesome_token")
}
