package discovery

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

func TestCrawlerBuildsSameOriginInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`
<a href="/search?q=neo">Search</a>
<a href="https://outside.example/admin">Outside</a>
<form action="/login" method="post"><input name="username"><input name="password"><input name="csrf"></form>
<form method="get"><input name="query"></form>
<script src="/assets/app.js"></script>
<script>const users = "/api/users?limit=10";</script>`))
		case "/search":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>result</html>"))
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`fetch("/api/orders"); const graph = "/graphql";`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	crawler := New(utils.NewHTTPClientWithOptions(utils.HTTPOptions{Retries: 0}), Options{MaxDepth: 1, MaxPages: 10, DiscoverScripts: true})
	inventory, err := crawler.Crawl(server.URL)
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if len(inventory.Pages) != 2 {
		t.Fatalf("expected root and discovered search page, got %#v", inventory.Pages)
	}
	if !containsEndpoint(inventory.Endpoints, server.URL+"/search?q=neo", "GET", "q") {
		t.Fatalf("missing discovered query endpoint: %#v", inventory.Endpoints)
	}
	if !containsEndpoint(inventory.Endpoints, server.URL+"/login", "POST") {
		t.Fatalf("missing discovered login endpoint: %#v", inventory.Endpoints)
	}
	if !containsForm(inventory.Forms, server.URL+"/login", "POST", "username", "password", "csrf") {
		t.Fatalf("missing login form: %#v", inventory.Forms)
	}
	if !containsForm(inventory.Forms, server.URL, "GET", "query") {
		t.Fatalf("missing empty-action form: %#v", inventory.Forms)
	}
	if len(inventory.Scripts) != 1 || inventory.Scripts[0] != server.URL+"/assets/app.js" {
		t.Fatalf("unexpected scripts: %#v", inventory.Scripts)
	}
	if len(inventory.APIs) != 3 || inventory.APIs[0] != server.URL+"/api/orders" || inventory.APIs[1] != server.URL+"/api/users?limit=10" || inventory.APIs[2] != server.URL+"/graphql" {
		t.Fatalf("unexpected API routes: %#v", inventory.APIs)
	}
	if !containsParameter(inventory.Parameters, "q", "query", server.URL+"/search?q=neo", "GET") {
		t.Fatalf("missing structured query parameter: %#v", inventory.Parameters)
	}
	if !containsParameter(inventory.Parameters, "username", "form", server.URL+"/login", "POST") {
		t.Fatalf("missing structured form parameter: %#v", inventory.Parameters)
	}

	inventory.SelectParameters([]string{" USERNAME , q", "username"})
	if len(inventory.SelectedParameters) != 2 || !containsParameter(inventory.SelectedParameters, "q", "query", server.URL+"/search?q=neo", "GET") || !containsParameter(inventory.SelectedParameters, "username", "form", server.URL+"/login", "POST") {
		t.Fatalf("unexpected selected parameters: %#v", inventory.SelectedParameters)
	}
}

func containsEndpoint(endpoints []Endpoint, rawURL, method string, parameters ...string) bool {
	for _, endpoint := range endpoints {
		if endpoint.URL == rawURL && endpoint.Method == method && len(endpoint.Parameters) == len(parameters) {
			matches := true
			for index := range parameters {
				if endpoint.Parameters[index] != parameters[index] {
					matches = false
				}
			}
			if matches {
				return true
			}
		}
	}
	return false
}

func containsForm(forms []Form, action, method string, fields ...string) bool {
	for _, form := range forms {
		if form.Action == action && form.Method == method && len(form.Fields) == len(fields) {
			fieldSet := make(map[string]struct{}, len(form.Fields))
			for _, field := range form.Fields {
				fieldSet[field] = struct{}{}
			}
			matches := true
			for _, field := range fields {
				if _, exists := fieldSet[field]; !exists {
					matches = false
				}
			}
			if matches {
				return true
			}
		}
	}
	return false
}

func containsParameter(parameters []Parameter, name, location, endpoint, method string) bool {
	for _, parameter := range parameters {
		if parameter.Name == name && parameter.Location == location && parameter.Endpoint == endpoint && parameter.Method == method {
			return true
		}
	}
	return false
}
