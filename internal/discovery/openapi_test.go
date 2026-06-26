package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

func TestDiscoverOpenAPIAddsOnlyOperations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"openapi":"3.0.0","paths":{"/api/users":{"get":{"parameters":[{"name":"search","in":"query"}]},"post":{},"parameters":{}},"/health":{"get":{}}}}`))
	}))
	defer server.Close()
	endpoints := DiscoverOpenAPI(context.Background(), utils.NewHTTPClientWithOptions(utils.HTTPOptions{Retries: 0}), server.URL)
	if len(endpoints) != 3 || !hasOpenAPIEndpoint(endpoints, server.URL+"/api/users", "GET") || !hasOpenAPIEndpoint(endpoints, server.URL+"/api/users", "POST") || !hasOpenAPIEndpoint(endpoints, server.URL+"/health", "GET") {
		t.Fatalf("unexpected OpenAPI endpoints: %#v", endpoints)
	}
	for _, endpoint := range endpoints {
		if endpoint.URL == server.URL+"/api/users" && endpoint.Method == "GET" && (len(endpoint.Parameters) != 1 || endpoint.Parameters[0] != "search") {
			t.Fatalf("missing OpenAPI query parameter: %#v", endpoint)
		}
	}
}

func hasOpenAPIEndpoint(endpoints []Endpoint, rawURL, method string) bool {
	for _, endpoint := range endpoints {
		if endpoint.URL == rawURL && endpoint.Method == method {
			return true
		}
	}
	return false
}
