package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/discovery"
	"github.com/khushi-nirsang/neoscanner/internal/templates"
)

// These fixtures are intentionally small and deterministic. They form the
// first validation-lab gate: a template must detect an actual vulnerable
// behavior and stay silent for the corresponding safe behavior.
func TestValidationLabReflectedXSS(t *testing.T) {
	payloadFile := writePayloadFile(t, "<script>alert(1)</script>\n")
	makeScanner := func() *Scanner {
		s := NewScanner(1, 2)
		s.ConfigureScanProfile("active")
		s.ConfigureActiveParameterTesting(true, 4, 1)
		s.templates = []*templates.Template{{ID: "xss-probe", Info: templates.Info{Name: "Reflected XSS", Severity: "medium"}, Requests: []templates.Request{{Payloads: []string{payloadFile}, Matchers: []templates.Matcher{{Type: "word", Part: "body", Words: []string{"{{payload}}"}}}}}}}
		return s
	}
	vulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.URL.Query().Get("q"))) }))
	defer vulnerable.Close()
	positive := makeScanner()
	positive.scanDiscoveredQueryParameters(vulnerable.URL, discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "q", Location: "query", Endpoint: vulnerable.URL + "?q=baseline", Method: http.MethodGet}}})
	if len(positive.Results.Items) != 1 {
		t.Fatalf("expected vulnerable reflection to be detected, got %#v", positive.Results.Items)
	}

	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("&lt;script&gt;alert(1)&lt;/script&gt;"))
	}))
	defer safe.Close()
	negative := makeScanner()
	negative.scanDiscoveredQueryParameters(safe.URL, discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "q", Location: "query", Endpoint: safe.URL + "?q=baseline", Method: http.MethodGet}}})
	if len(negative.Results.Items) != 0 {
		t.Fatalf("escaped reflection must not be reported as XSS: %#v", negative.Results.Items)
	}
}

func TestValidationLabErrorBasedSQLi(t *testing.T) {
	payloadFile := writePayloadFile(t, "'\n")
	makeScanner := func() *Scanner {
		s := NewScanner(1, 2)
		s.ConfigureScanProfile("active")
		s.ConfigureActiveParameterTesting(true, 4, 1)
		s.templates = []*templates.Template{{ID: "sql-injection", Info: templates.Info{Name: "SQL Injection", Severity: "critical"}, Requests: []templates.Request{{Payloads: []string{payloadFile}, Matchers: []templates.Matcher{{Type: "regex", Part: "body", Regex: []string{"(?i)sql syntax"}}}}}}}
		return s
	}
	vulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "'" {
			_, _ = w.Write([]byte("SQL syntax error"))
			return
		}
		_, _ = w.Write([]byte("normal page"))
	}))
	defer vulnerable.Close()
	positive := makeScanner()
	positive.scanDiscoveredQueryParameters(vulnerable.URL, discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "id", Location: "query", Endpoint: vulnerable.URL + "?id=1", Method: http.MethodGet}}})
	if len(positive.Results.Items) != 1 {
		t.Fatalf("expected SQL error behavior to be detected, got %#v", positive.Results.Items)
	}

	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("normal page")) }))
	defer safe.Close()
	negative := makeScanner()
	negative.scanDiscoveredQueryParameters(safe.URL, discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "id", Location: "query", Endpoint: safe.URL + "?id=1", Method: http.MethodGet}}})
	if len(negative.Results.Items) != 0 {
		t.Fatalf("clean response must not be reported as SQLi: %#v", negative.Results.Items)
	}
}

func TestValidationLabSSTIAndSSRF(t *testing.T) {
	t.Run("ssti evaluation", func(t *testing.T) {
		payloadFile := writePayloadFile(t, "{{7*7}}\n")
		makeScanner := func() *Scanner {
			s := NewScanner(1, 2)
			s.ConfigureScanProfile("active")
			s.ConfigureActiveParameterTesting(true, 4, 1)
			s.templates = []*templates.Template{{ID: "ssti-detection", Info: templates.Info{Name: "SSTI", Severity: "high"}, Requests: []templates.Request{{Payloads: []string{payloadFile}, Matchers: []templates.Matcher{{Type: "word", Part: "body", Words: []string{"49"}}}}}}}
			return s
		}
		vulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("q") == "{{7*7}}" {
				_, _ = w.Write([]byte("49"))
				return
			}
			_, _ = w.Write([]byte("template page"))
		}))
		defer vulnerable.Close()
		positive := makeScanner()
		positive.scanDiscoveredQueryParameters(vulnerable.URL, discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "q", Location: "query", Endpoint: vulnerable.URL + "?q=baseline", Method: http.MethodGet}}})
		if len(positive.Results.Items) != 1 {
			t.Fatalf("expected SSTI finding, got %#v", positive.Results.Items)
		}
		safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.URL.Query().Get("q"))) }))
		defer safe.Close()
		negative := makeScanner()
		negative.scanDiscoveredQueryParameters(safe.URL, discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "q", Location: "query", Endpoint: safe.URL + "?q=baseline", Method: http.MethodGet}}})
		if len(negative.Results.Items) != 0 {
			t.Fatalf("literal SSTI payload must not be reported: %#v", negative.Results.Items)
		}
	})
	t.Run("ssrf server-side signal", func(t *testing.T) {
		payloadFile := writePayloadFile(t, "http://169.254.169.254/latest/meta-data/\n")
		makeScanner := func() *Scanner {
			s := NewScanner(1, 2)
			s.ConfigureScanProfile("active")
			s.ConfigureActiveParameterTesting(true, 4, 1)
			s.templates = []*templates.Template{{ID: "ssrf-probe", Info: templates.Info{Name: "SSRF", Severity: "high"}, Requests: []templates.Request{{Payloads: []string{payloadFile}, MatchersCondition: "and", Matchers: []templates.Matcher{{Type: "word", Part: "body", Words: []string{"ami-id"}}, {Type: "word", Part: "body", Words: []string{"requested resource"}, Negative: true}}}}}}
			return s
		}
		vulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("url") != "baseline" {
				_, _ = w.Write([]byte("ami-id: i-123"))
				return
			}
			_, _ = w.Write([]byte("normal page"))
		}))
		defer vulnerable.Close()
		positive := makeScanner()
		positive.scanDiscoveredQueryParameters(vulnerable.URL, discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "url", Location: "query", Endpoint: vulnerable.URL + "?url=baseline", Method: http.MethodGet}}})
		if len(positive.Results.Items) != 1 {
			t.Fatalf("expected SSRF finding, got %#v", positive.Results.Items)
		}
		safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("requested resource ami-id is not available"))
		}))
		defer safe.Close()
		negative := makeScanner()
		negative.scanDiscoveredQueryParameters(safe.URL, discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "url", Location: "query", Endpoint: safe.URL + "?url=baseline", Method: http.MethodGet}}})
		if len(negative.Results.Items) != 0 {
			t.Fatalf("rejected SSRF input must not be reported: %#v", negative.Results.Items)
		}
	})
}

func TestValidationLabAuthenticationBypass(t *testing.T) {
	payloadFile := writePayloadFile(t, "admin:password\n")
	makeTemplate := func(path string) *templates.Template {
		return &templates.Template{ID: "authentication-bypass", Info: templates.Info{Name: "Authentication Bypass", Severity: "critical"}, Requests: []templates.Request{{Method: http.MethodPost, Path: []string{path}, Payloads: []string{payloadFile}, Matchers: []templates.Matcher{{Type: "word", Part: "body", Words: []string{"account summary"}}}}}}
	}
	positiveServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/doLogin" {
			http.Redirect(w, r, "/bank/main", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("account summary"))
	}))
	defer positiveServer.Close()
	positive := NewScanner(1, 2)
	positive.executeTemplate(makeTemplate("{{BaseURL}}/doLogin"), positiveServer.URL)
	if len(positive.Results.Items) != 1 {
		t.Fatalf("expected authenticated-area signal to be reported, got %#v", positive.Results.Items)
	}
	negativeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("account summary")) }))
	defer negativeServer.Close()
	negative := NewScanner(1, 2)
	negative.executeTemplate(makeTemplate("{{BaseURL}}/login"), negativeServer.URL)
	if len(negative.Results.Items) != 0 {
		t.Fatalf("login route must not be reported as bypass: %#v", negative.Results.Items)
	}
}

func TestValidationLabCSRFTokenPresence(t *testing.T) {
	scanner := NewScanner(1, 2)
	scanner.scanDiscoveredCSRF("https://app.test", discovery.Inventory{Forms: []discovery.Form{
		{Action: "https://app.test/profile", Method: http.MethodPost, Fields: []string{"email", "csrf_token"}},
		{Action: "https://app.test/feedback", Method: http.MethodPost, Fields: []string{"message"}},
	}})
	if len(scanner.Results.Items) != 1 || scanner.Results.Items[0].MatchedURL != "https://app.test/feedback" || scanner.Results.Items[0].Confidence != "potential" {
		t.Fatalf("expected only tokenless form as potential CSRF finding: %#v", scanner.Results.Items)
	}
}

func TestValidationLabAuthenticationBypassRejectsLoginRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/doLogin" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("sign off"))
	}))
	defer server.Close()
	scanner := NewScanner(1, 2)
	scanner.ConfigureScanProfile("active")
	scanner.templates = []*templates.Template{{ID: "authentication-bypass", Info: templates.Info{Name: "Authentication Bypass", Severity: "critical"}, Requests: []templates.Request{{Method: http.MethodPost, Path: []string{"{{BaseURL}}/doLogin"}, Matchers: []templates.Matcher{{Type: "word", Part: "body", Words: []string{"sign off"}}}}}}}
	scanner.executeTemplate(scanner.templates[0], server.URL)
	if len(scanner.Results.Items) != 0 {
		t.Fatalf("login redirect must never be reported as bypass: %#v", scanner.Results.Items)
	}
}

func TestValidationLabOpenRedirectRequiresExternalLocation(t *testing.T) {
	payloadFile := writePayloadFile(t, "https://evil.com/callback\n")
	noRedirects := false
	makeTemplate := func() *templates.Template {
		return &templates.Template{ID: "open-redirect", Info: templates.Info{Name: "Open Redirect", Severity: "medium"}, Requests: []templates.Request{{
			Method: http.MethodGet, Redirects: &noRedirects, Path: []string{"{{BaseURL}}/redirect?url={{payload}}"}, Payloads: []string{payloadFile}, MatchersCondition: "and",
			Matchers: []templates.Matcher{{Type: "status", Status: []int{302}}, {Type: "regex", Part: "header", Regex: []string{"(?i)location:.*evil\\.com"}}},
		}}}
	}
	vulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("url"), http.StatusFound)
	}))
	defer vulnerable.Close()
	positive := NewScanner(1, 2)
	positive.executeTemplate(makeTemplate(), vulnerable.URL)
	if len(positive.Results.Items) != 1 {
		t.Fatalf("expected external redirect to be reported, got %#v", positive.Results.Items)
	}

	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?next=evil.com", http.StatusFound)
	}))
	defer safe.Close()
	negative := NewScanner(1, 2)
	negative.executeTemplate(makeTemplate(), safe.URL)
	if len(negative.Results.Items) != 0 {
		t.Fatalf("same-site redirects must not be reported as open redirects: %#v", negative.Results.Items)
	}
}

func TestValidationLabFileDisclosureRequiresStrongMarker(t *testing.T) {
	payloadFile := writePayloadFile(t, "../../../../etc/passwd\n")
	makeTemplate := func(id string) *templates.Template {
		return &templates.Template{ID: id, Info: templates.Info{Name: "File Disclosure", Severity: "high"}, Requests: []templates.Request{{
			Method: http.MethodGet, Path: []string{"{{BaseURL}}/download?file={{payload}}"}, Payloads: []string{payloadFile}, MatchersCondition: "and",
			Matchers:   []templates.Matcher{{Type: "status", Status: []int{200}}, {Type: "word", Part: "body", Words: []string{"nginx", "root:x:"}}},
			Extractors: []templates.Extractor{{Type: "regex", Part: "body", Regex: []string{"root:.*:0:0:"}}},
		}}}
	}
	vulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
	}))
	defer vulnerable.Close()
	positive := NewScanner(1, 2)
	positive.executeTemplate(makeTemplate("local-file-inclusion"), vulnerable.URL)
	if len(positive.Results.Items) != 1 || len(positive.Results.Items[0].Evidence) == 0 {
		t.Fatalf("expected strong file disclosure evidence, got %#v", positive.Results.Items)
	}

	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Welcome to nginx"))
	}))
	defer safe.Close()
	negative := NewScanner(1, 2)
	negative.executeTemplate(makeTemplate("path-traversal"), safe.URL)
	if len(negative.Results.Items) != 0 {
		t.Fatalf("generic server words must not be reported as file disclosure: %#v", negative.Results.Items)
	}
}

func TestValidationLabCommandInjectionRequiresExecutionMarker(t *testing.T) {
	payloadFile := writePayloadFile(t, ";id\n")
	makeTemplate := func() *templates.Template {
		return &templates.Template{ID: "command-injection", Info: templates.Info{Name: "Command Injection", Severity: "critical"}, Requests: []templates.Request{{
			Method: http.MethodGet, Path: []string{"{{BaseURL}}/ping?host={{payload}}"}, Payloads: []string{payloadFile}, MatchersCondition: "and",
			Matchers: []templates.Matcher{{Type: "status", Status: []int{200}}, {Type: "word", Part: "body", Words: []string{"uid=", "PONG"}}},
		}}}
	}
	vulnerable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("uid=1000(scanner) gid=1000(scanner)"))
	}))
	defer vulnerable.Close()
	positive := NewScanner(1, 2)
	positive.executeTemplate(makeTemplate(), vulnerable.URL)
	if len(positive.Results.Items) != 1 {
		t.Fatalf("expected command execution marker to be reported, got %#v", positive.Results.Items)
	}

	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("PONG from application health check"))
	}))
	defer safe.Close()
	negative := NewScanner(1, 2)
	negative.executeTemplate(makeTemplate(), safe.URL)
	if len(negative.Results.Items) != 0 {
		t.Fatalf("generic application PONG must not be reported as command injection: %#v", negative.Results.Items)
	}
}
