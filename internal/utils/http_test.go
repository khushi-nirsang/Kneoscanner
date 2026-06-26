package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPClientRetainsCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "test-session"})
			return
		}
		if _, err := r.Cookie("session"); err != nil {
			http.Error(w, "missing session", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewHTTPClientWithOptions(HTTPOptions{Retries: 0})
	if _, err := client.Get(server.URL + "/set"); err != nil {
		t.Fatalf("set cookie: %v", err)
	}
	response, err := client.Get(server.URL + "/protected")
	if err != nil {
		t.Fatalf("request protected route: %v", err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected retained cookie to authorize request, got %d", response.StatusCode)
	}
}

func TestHTTPClientCanKeepRedirectResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	follow := false
	client := NewHTTPClientWithOptions(HTTPOptions{FollowRedirects: true, Retries: 0})
	response, err := client.DoWithOptions(http.MethodGet, server.URL+"/start", nil, "", RequestOptions{FollowRedirects: &follow})
	if err != nil {
		t.Fatalf("request redirect: %v", err)
	}
	if response.StatusCode != http.StatusFound || response.FinalURL != server.URL+"/start" {
		t.Fatalf("expected original redirect response, got status=%d final=%s", response.StatusCode, response.FinalURL)
	}
}

func TestHTTPClientDoesNotFollowCrossOriginScopedRedirect(t *testing.T) {
	var externalCalls atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		externalCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer external.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, external.URL+"/outside", http.StatusFound)
	}))
	defer target.Close()
	client := NewHTTPClientWithOptions(HTTPOptions{Retries: 0, FollowRedirects: true})
	response, err := client.GetScopedContext(context.Background(), target.URL, target.URL)
	if err != nil || response.StatusCode != http.StatusFound || externalCalls.Load() != 0 {
		t.Fatalf("cross-origin redirect escaped scope: response=%v err=%v calls=%d", response, err, externalCalls.Load())
	}
}

func TestHTTPClientLimitsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer server.Close()

	client := NewHTTPClientWithOptions(HTTPOptions{MaxResponseBytes: 4, Retries: 0})
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request response body: %v", err)
	}
	if response.BodyContent != "0123" || !response.Truncated {
		t.Fatalf("expected a truncated four-byte body, got %q truncated=%t", response.BodyContent, response.Truncated)
	}
}

func TestHTTPClientRetriesSafeRequests(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := NewHTTPClientWithOptions(HTTPOptions{Retries: 1, RetryDelay: time.Millisecond})
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("retry request: %v", err)
	}
	if response.Attempts != 2 || response.StatusCode != http.StatusOK {
		t.Fatalf("expected successful second request, got attempts=%d status=%d", response.Attempts, response.StatusCode)
	}
}

func TestHTTPClientAppliesConfiguredAuthenticationHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer scanner-token" || r.Header.Get("X-Tenant") != "security" {
			http.Error(w, "missing configured authentication", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := NewHTTPClientWithOptions(HTTPOptions{Retries: 0, DefaultHeaders: map[string]string{"Authorization": "Bearer scanner-token", "X-Tenant": "security"}})
	response, err := client.Get(server.URL)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("configured headers were not applied: response=%v err=%v", response, err)
	}
}

func TestHTTPClientCanWithholdDefaultAuthenticationHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("authentication header leaked: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := NewHTTPClientWithOptions(HTTPOptions{Retries: 0, DefaultHeaders: map[string]string{"Authorization": "Bearer secret"}})
	response, err := client.DoWithOptions(http.MethodGet, server.URL, nil, "", RequestOptions{SkipDefaultHeaders: true})
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("request failed: response=%v err=%v", response, err)
	}
}
