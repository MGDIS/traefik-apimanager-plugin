package traefik_apimanager_plugin_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apimanager "github.com/MGDIS/traefik-apimanager-plugin"
)

// captureStdout captures everything written to stdout during fn execution
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	fn() // Execute the function that writes to stdout

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("failed to read from pipe: %v", err)
	}

	return buf.String()
}

// assertLogContains checks if the log output contains expected messages
func assertLogContains(t *testing.T, logOutput string, expectedMessages ...string) {
	t.Helper()

	for _, msg := range expectedMessages {
		if !strings.Contains(logOutput, msg) {
			t.Errorf("expected log to contain %q, but got %q", msg, logOutput)
		}
	}
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("expected header value %s, but got %s", expected, req.Header.Get(key))
	}
}

func TestEmptyAuthModeLog(t *testing.T) {
	cfg := apimanager.CreateConfig()
	cfg.AuthMode = ""

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	logOutput := captureStdout(t, func() {
		_, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
		if err != nil {
			t.Fatal(err)
		}
	})

	assertLogContains(t, logOutput,
		"traefik-api-manager - empty auth mode",
		"traefik-api-manager - default auth mode used",
	)
}

func TestInvalidAuthModeLog(t *testing.T) {
	cfg := apimanager.CreateConfig()
	cfg.AuthMode = "invalid"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	logOutput := captureStdout(t, func() {
		_, err := apimanager.New(ctx, next, cfg, "apimanager-plugin")
		if err != nil {
			t.Fatal(err)
		}
	})

	assertLogContains(t, logOutput,
		"traefik-api-manager - invalid auth mode",
		"traefik-api-manager - default auth mode used",
	)
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

// oauth2TestConfig builds a minimal oauth2 config pointing at the given mock URL.
func oauth2TestConfig(url string) *apimanager.Config {
	cfg := apimanager.CreateConfig()
	cfg.APIManagerURL = url
	cfg.AuthMode = "oauth2"
	cfg.ClientID = "clientID"
	cfg.ClientSecret = "clientSecret"
	cfg.Username = "user"
	cfg.Password = "pass"
	cfg.GrantType = "password"
	return cfg
}

func serveOAuth2(t *testing.T, handler http.Handler) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(httptest.NewRecorder(), req)
	assertHeader(t, req, "Authorization", "Bearer apimanager_token")
}

// TestOAuth2TokenIsCached - while a token with a server-provided expires_in is still
// valid, repeated requests reuse it and the API manager is called only once.
func TestOAuth2TokenIsCached(t *testing.T) {
	var calls int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token", "expires_in": 3600}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	handler, err := apimanager.New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), oauth2TestConfig(mockServer.URL), "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		serveOAuth2(t, handler)
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected API manager to be called once (token cached), got %d", got)
	}
}

// TestOAuth2TokenRefreshedAfterExpiry - once the server-provided lifetime elapses,
// the next request re-fetches the token.
func TestOAuth2TokenRefreshedAfterExpiry(t *testing.T) {
	var calls int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token", "expires_in": 2}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	cfg := oauth2TestConfig(mockServer.URL)
	cfg.Margin = 1 // 2s lifetime - 1s margin => cached ~1s (also proves the margin is applied)

	handler, err := apimanager.New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	serveOAuth2(t, handler)
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 call after first request, got %d", got)
	}

	time.Sleep(1200 * time.Millisecond) // past the ~1s cached window

	serveOAuth2(t, handler)
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected token refresh after expiry (2 calls), got %d", got)
	}
}

// TestOAuth2NoCacheWithoutExpiresIn - with no expires_in in the response, the plugin
// must not cache: it fetches a fresh token on every request, exactly as before.
func TestOAuth2NoCacheWithoutExpiresIn(t *testing.T) {
	var calls int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token"}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	handler, err := apimanager.New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), oauth2TestConfig(mockServer.URL), "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		serveOAuth2(t, handler)
	}

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected a fetch per request when the server sends no expires_in (3 calls), got %d", got)
	}
}

// TestOAuth2NoCacheWhenMarginExceedsLifetime - if the refresh margin does not fit
// within the token's lifetime there is no safety buffer, so the plugin must not
// cache and must fetch on every request.
func TestOAuth2NoCacheWhenMarginExceedsLifetime(t *testing.T) {
	var calls int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token", "expires_in": 5}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	cfg := oauth2TestConfig(mockServer.URL)
	cfg.Margin = 10 // margin (10s) > lifetime (5s) => no safety buffer => must not cache

	handler, err := apimanager.New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), cfg, "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		serveOAuth2(t, handler)
	}

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected a fetch per request when margin exceeds lifetime (3 calls), got %d", got)
	}
}

// TestOAuth2ConcurrentReadsHitCache - once the token is cached, many concurrent
// requests all reuse it (no extra fetches) and the race detector stays clean.
func TestOAuth2ConcurrentReadsHitCache(t *testing.T) {
	var calls int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token", "expires_in": 3600}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	handler, err := apimanager.New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), oauth2TestConfig(mockServer.URL), "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	serveOAuth2(t, handler) // warm the cache: 1 fetch

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Errorf("failed to build request: %v", err)
				return
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)
			assertHeader(t, req, "Authorization", "Bearer apimanager_token")
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected concurrent requests to reuse the cached token (1 fetch), got %d", got)
	}
}

// TestOAuth2ConcurrentRefreshCoalesces - when many requests hit a cold cache at once,
// only one goroutine calls the API manager; the rest wait and reuse its token. The
// mock sleeps to widen the race window so an uncoalesced implementation would fan out.
func TestOAuth2ConcurrentRefreshCoalesces(t *testing.T) {
	var calls int32
	mockServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(50 * time.Millisecond)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte(`{"access_token": "apimanager_token", "expires_in": 3600}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer mockServer.Close()

	handler, err := apimanager.New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), oauth2TestConfig(mockServer.URL), "apimanager-plugin")
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost", nil)
			if err != nil {
				t.Errorf("failed to build request: %v", err)
				return
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)
			assertHeader(t, req, "Authorization", "Bearer apimanager_token")
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected concurrent cold-cache requests to coalesce into 1 fetch, got %d", got)
	}
}
