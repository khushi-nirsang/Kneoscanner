package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/discovery"
	"github.com/khushi-nirsang/neoscanner/internal/templates"
	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

func TestBuildRequestURLRendersBaseURL(t *testing.T) {

	got := buildRequestURL(
		"https://example.com/root",
		"{{BaseURL}}/.git/HEAD",
		"",
	)

	want := "https://example.com/root/.git/HEAD"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestSaveResultsReturnsReportWriteErrors(t *testing.T) {
	scanner := NewScanner(1, 1)
	if err := scanner.SaveResultsWithOptions(t.TempDir(), true, false, false); err == nil {
		t.Fatal("expected JSON report save error when output path is a directory")
	}
}

func TestBuildRequestURLEscapesPayload(t *testing.T) {

	got := buildRequestURL(
		"https://example.com",
		"{{BaseURL}}/?q={{payload}}",
		"<%= 7*7 %>",
	)

	want := "https://example.com/?q=%3C%25%3D+7%2A7+%25%3E"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestReplaceQueryParameterAddsDocumentedParameter(t *testing.T) {
	mutated, ok := replaceQueryParameter("https://example.test/api/users", "search", "neo")
	if !ok || mutated != "https://example.test/api/users?search=neo" {
		t.Fatalf("expected documented parameter to be added, got %q ok=%t", mutated, ok)
	}
}

func TestMatchResponseStatus(t *testing.T) {

	scanner := NewScanner(1, 1)

	resp := &utils.Response{
		Response: &http.Response{
			StatusCode: 403,
			Header:     http.Header{},
		},
	}

	matcher := templates.Matcher{
		Type:   "status",
		Status: []int{200, 403},
	}

	if !scanner.matchResponse(resp, matcher, "") {
		t.Fatal("expected status matcher to match")
	}
}

func TestMatchResponseNegativeHeaderRegex(t *testing.T) {

	scanner := NewScanner(1, 1)

	resp := &utils.Response{
		Response: &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Server": []string{"nginx"},
			},
		},
	}

	matcher := templates.Matcher{
		Type:     "regex",
		Part:     "header",
		Regex:    templates.StringSlice{"(?i)x-frame-options"},
		Negative: true,
	}

	if !scanner.matchResponse(resp, matcher, "") {
		t.Fatal("expected negative regex matcher to succeed")
	}
}

func TestMatchMatchersAndCondition(t *testing.T) {

	scanner := NewScanner(1, 1)

	resp := &utils.Response{
		Response: &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
		},
		BodyContent: "admin login",
	}

	matchers := []templates.Matcher{
		{
			Type:  "word",
			Part:  "body",
			Words: []string{"admin"},
		},
		{
			Type:  "word",
			Part:  "body",
			Words: []string{"missing"},
		},
	}

	if scanner.matchMatchers(resp, matchers, "and", "") {
		t.Fatal("expected AND condition to fail")
	}

	if !scanner.matchMatchers(resp, matchers, "or", "") {
		t.Fatal("expected OR condition to succeed")
	}
}

func TestMatchResponseRendersPayloadPlaceholder(t *testing.T) {

	scanner := NewScanner(1, 1)

	resp := &utils.Response{
		Response: &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
		},
		BodyContent: "reflected <script>alert(1)</script>",
	}

	matcher := templates.Matcher{
		Type:  "word",
		Part:  "body",
		Words: []string{"{{payload}}"},
	}

	if !scanner.matchResponse(resp, matcher, "<script>alert(1)</script>") {
		t.Fatal("expected payload placeholder matcher to match reflected payload")
	}
}

func TestIsLoginRoute(t *testing.T) {
	if !isLoginRoute("https://example.test/login.jsp") || !isLoginRoute("https://example.test/auth/signin") {
		t.Fatal("expected login routes to be identified")
	}
	if isLoginRoute("https://example.test/bank/main.jsp") {
		t.Fatal("did not expect an authenticated application route to be rejected")
	}
}

func TestExecuteTemplateExpandsPathPayloads(t *testing.T) {

	payloadFile := writePayloadFile(t, "alpha\nbeta\nalpha\n")

	var mu sync.Mutex
	seen := make(map[string]int)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Query().Get("q")]++
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	scanner := NewScanner(2, 2)
	scanner.executeTemplate(
		&templates.Template{
			ID: "payload-path",
			Info: templates.Info{
				Name:     "Payload Path",
				Severity: "info",
			},
			Requests: []templates.Request{
				{
					Method:   "GET",
					Path:     []string{"{{BaseURL}}/?q={{payload}}"},
					Payloads: []string{payloadFile},
					Matchers: []templates.Matcher{
						{
							Type:   "status",
							Status: []int{200},
						},
					},
				},
			},
		},
		server.URL,
	)

	mu.Lock()
	defer mu.Unlock()

	if seen["alpha"] != 1 || seen["beta"] != 1 {
		t.Fatalf("expected unique payload requests, got %#v", seen)
	}

	if got := len(scanner.Results.Items); got != 1 {
		t.Fatalf("expected one finding for payload variants sent to the same parameter, got %d", got)
	}
}

func TestActiveScanRunsDiscoveryDrivenTemplateFallback(t *testing.T) {
	payloadFile := writePayloadFile(t, "<script>alert(1)</script>\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Query().Get("q"))
	}))
	defer server.Close()

	scanner := NewScanner(1, 2)
	scanner.ConfigureScanProfile("active")
	scanner.templates = []*templates.Template{
		{
			ID: "xss-probe",
			Info: templates.Info{
				Name:     "Reflected XSS",
				Severity: "high",
			},
			Requests: []templates.Request{
				{
					Method:   "GET",
					Path:     []string{"{{BaseURL}}/?q={{payload}}"},
					Payloads: []string{payloadFile},
					Matchers: []templates.Matcher{
						{
							Type:  "word",
							Part:  "body",
							Words: []string{"{{payload}}"},
						},
					},
				},
			},
		},
	}

	scanner.StartScan(server.URL)

	if len(scanner.Results.Items) == 0 {
		t.Fatal("expected active template fallback to create a finding")
	}
	found := false
	for _, item := range scanner.Results.Items {
		if item.TemplateID == "xss-probe" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected xss-probe finding, got %#v", scanner.Results.Items)
	}
}

func TestResultsDeduplicateQueryPayloadVariantsAndKeepEvidence(t *testing.T) {
	results := NewResults()
	first := ScanResult{Target: "https://example.test", TemplateID: "xss", Method: http.MethodGet, MatchedURL: "https://example.test/search?q=first", Payload: "first"}
	second := first
	second.MatchedURL = "https://example.test/search?q=second"
	second.Payload = "second"
	if !results.Add(first) || results.Add(second) {
		t.Fatal("expected only the first payload variant to be stored")
	}
	if len(results.Items) != 1 || results.Items[0].Payload != "first" {
		t.Fatalf("expected first payload to be retained as evidence, got %#v", results.Items)
	}
}

func TestExecuteTemplateExpandsBodyPayloadsAndDeduplicatesFindings(t *testing.T) {

	payloadFile := writePayloadFile(t, "first\nsecond\n")

	var mu sync.Mutex
	seenBodies := make(map[string]int)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}

		mu.Lock()
		seenBodies[string(body)]++
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	scanner := NewScanner(2, 2)
	scanner.executeTemplate(
		&templates.Template{
			ID: "payload-body",
			Info: templates.Info{
				Name:     "Payload Body",
				Severity: "info",
			},
			Requests: []templates.Request{
				{
					Method:   "POST",
					Path:     []string{"{{BaseURL}}/submit"},
					Body:     "value={{payload}}",
					Payloads: []string{payloadFile},
					Matchers: []templates.Matcher{
						{
							Type:   "status",
							Status: []int{200},
						},
					},
				},
			},
		},
		server.URL,
	)

	mu.Lock()
	defer mu.Unlock()

	if seenBodies["value=first"] != 1 || seenBodies["value=second"] != 1 {
		t.Fatalf("expected body payload requests, got %#v", seenBodies)
	}

	if got := len(scanner.Results.Items); got != 1 {
		t.Fatalf("expected same-URL POST findings to dedupe to 1, got %d", got)
	}
}

func TestDiscoveredQueryParameterMutationUsesBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("search results " + r.URL.Query().Get("q")))
	}))
	defer server.Close()

	payloadFile := writePayloadFile(t, "marker-xss\n")
	scanner := NewScanner(1, 2)
	scanner.ConfigureScanProfile("active")
	scanner.ConfigureActiveParameterTesting(true, 5, 1)
	scanner.templates = []*templates.Template{{
		ID:   "xss-probe",
		Info: templates.Info{Name: "Reflected XSS", Severity: "medium"},
		Requests: []templates.Request{{
			Payloads: []string{payloadFile},
			Matchers: []templates.Matcher{{Type: "word", Part: "body", Words: []string{"{{payload}}"}}},
		}},
	}}

	inventory := discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "q", Location: "query", Endpoint: server.URL + "?q=baseline", Method: http.MethodGet}}}
	scanner.scanDiscoveredQueryParameters(server.URL, inventory)
	if got := len(scanner.Results.Items); got != 1 {
		t.Fatalf("expected one mutation-specific finding, got %d", got)
	}
}

func TestDiscoveredGETFormMutationUsesFormDefaults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("search results " + r.URL.Query().Get("q")))
	}))
	defer server.Close()

	payloadFile := writePayloadFile(t, "form-marker\n")
	scanner := NewScanner(1, 2)
	scanner.ConfigureScanProfile("active")
	scanner.ConfigureActiveParameterTesting(true, 5, 1)
	scanner.templates = []*templates.Template{{
		ID:       "xss-probe",
		Info:     templates.Info{Name: "Reflected XSS", Severity: "medium"},
		Requests: []templates.Request{{Payloads: []string{payloadFile}, Matchers: []templates.Matcher{{Type: "word", Part: "body", Words: []string{"{{payload}}"}}}}},
	}}

	inventory := discovery.Inventory{
		Forms:              []discovery.Form{{Action: server.URL, Method: http.MethodGet, Fields: []string{"q"}, Defaults: map[string]string{"q": "baseline"}}},
		SelectedParameters: []discovery.Parameter{{Name: "q", Location: "form", Endpoint: server.URL, Method: http.MethodGet}},
	}
	scanner.scanDiscoveredQueryParameters(server.URL, inventory)
	if got := len(scanner.Results.Items); got != 1 {
		t.Fatalf("expected one GET form finding, got %d", got)
	}
}

func TestDiscoveredPOSTFormMutationIsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	payloadFile := writePayloadFile(t, "post-marker\n")
	scanner := NewScanner(1, 2)
	scanner.ConfigureScanProfile("active")
	scanner.ConfigurePostFormTesting(true, 5)
	scanner.payloadsPerParameter = 1
	scanner.templates = []*templates.Template{{
		ID:       "xss-probe",
		Info:     templates.Info{Name: "Reflected XSS", Severity: "medium"},
		Requests: []templates.Request{{Payloads: []string{payloadFile}, Matchers: []templates.Matcher{{Type: "word", Part: "body", Words: []string{"{{payload}}"}}}}},
	}}
	inventory := discovery.Inventory{
		Forms:              []discovery.Form{{Action: server.URL, Method: http.MethodPost, Fields: []string{"note"}, Defaults: map[string]string{"note": "baseline"}}},
		SelectedParameters: []discovery.Parameter{{Name: "note", Location: "form", Endpoint: server.URL, Method: http.MethodPost}},
	}
	scanner.scanDiscoveredPOSTForms(server.URL, inventory)
	if got := len(scanner.Results.Items); got != 1 {
		t.Fatalf("expected one explicit POST form finding, got %d", got)
	}
}

func TestDiscoveredMutationsRespectTemplateRiskProfile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("host") == "baseline" {
			_, _ = w.Write([]byte("normal ping page"))
			return
		}
		_, _ = w.Write([]byte("uid=1000(scanner) gid=1000(scanner)"))
	}))
	defer server.Close()

	payloadFile := writePayloadFile(t, ";id\n")
	makeScanner := func(profile string) *Scanner {
		scanner := NewScanner(1, 2)
		scanner.ConfigureScanProfile(profile)
		scanner.ConfigureActiveParameterTesting(true, 5, 1)
		scanner.templates = []*templates.Template{{
			ID:   "command-injection",
			Info: templates.Info{Name: "Command Injection", Severity: "critical"},
			Requests: []templates.Request{{
				Payloads:          []string{payloadFile},
				MatchersCondition: "and",
				Matchers: []templates.Matcher{
					{Type: "status", Status: []int{200}},
					{Type: "word", Part: "body", Words: []string{"uid="}},
				},
			}},
		}}
		return scanner
	}
	inventory := discovery.Inventory{SelectedParameters: []discovery.Parameter{{Name: "host", Location: "query", Endpoint: server.URL + "?host=baseline", Method: http.MethodGet}}}
	active := makeScanner("active")
	active.scanDiscoveredQueryParameters(server.URL, inventory)
	if len(active.Results.Items) != 0 {
		t.Fatalf("active profile must not run intrusive command injection templates: %#v", active.Results.Items)
	}
	intrusive := makeScanner("intrusive")
	intrusive.scanDiscoveredQueryParameters(server.URL, inventory)
	if len(intrusive.Results.Items) != 1 {
		t.Fatalf("intrusive profile should run command injection templates, got %#v", intrusive.Results.Items)
	}
}

func TestIsDiscoveryDrivenTemplate(t *testing.T) {
	if !isDiscoveryDrivenTemplate("xss-probe") || !isDiscoveryDrivenTemplate("sql-injection") || !isDiscoveryDrivenTemplate("ssti-detection") || !isDiscoveryDrivenTemplate("ssrf-probe") || !isDiscoveryDrivenTemplate("open-redirect") || !isDiscoveryDrivenTemplate("path-traversal") || !isDiscoveryDrivenTemplate("command-injection") {
		t.Fatal("expected active/intrusive input-mutation templates to be discovery-driven")
	}
	if isDiscoveryDrivenTemplate("idor-detection") {
		t.Fatal("IDOR is not discovery-driven yet")
	}
}

func TestTemplateRiskProfiles(t *testing.T) {
	if got := templateRisk(&templates.Template{ID: "custom", Info: templates.Info{Risk: "intrusive"}}); got != "intrusive" {
		t.Fatalf("expected explicit template risk, got %s", got)
	}
	if got := templateRisk(&templates.Template{ID: "race-condition"}); got != "intrusive" {
		t.Fatalf("expected intrusive race test, got %s", got)
	}
	if got := templateRisk(&templates.Template{ID: "xss-probe", Requests: []templates.Request{{Method: http.MethodGet}}}); got != "active" {
		t.Fatalf("expected active XSS template, got %s", got)
	}
	if got := templateRisk(&templates.Template{ID: "authentication-bypass"}); got != "active" {
		t.Fatalf("expected active auth template, got %s", got)
	}
}

func TestPassiveSecurityConfigurationFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Security-Policy", "default-src *; script-src 'self' 'unsafe-inline'")
		w.Header().Set("Server", "demo-server/1.0")
		w.Header().Set("X-Powered-By", "DemoFramework")
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "test"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	scanner := NewScanner(1, 2)
	scanner.scanSecurityConfiguration(server.URL)
	if got := len(scanner.Results.Items); got != 9 {
		t.Fatalf("expected missing headers, passive exposure, CORS, CSP, and cookie findings, got %d", got)
	}
	seen := map[string]bool{}
	for _, finding := range scanner.Results.Items {
		if finding.OWASPCategory == "" || finding.Confidence != "confirmed" {
			t.Fatalf("expected OWASP category and confidence, got %#v", finding)
		}
		seen[finding.Name] = true
	}
	for _, name := range []string{"Permissive CORS Policy", "Weak Content Security Policy", "Server Version Disclosure", "X-Powered-By Disclosure", "Session Cookie Missing SameSite"} {
		if !seen[name] {
			t.Fatalf("expected passive finding %q, got %#v", name, seen)
		}
	}
}

func TestDiscoveredCSRFCheckUsesRealPostForms(t *testing.T) {
	scanner := NewScanner(1, 2)
	inventory := discovery.Inventory{Forms: []discovery.Form{
		{Action: "https://example.test/feedback", Method: http.MethodPost, Fields: []string{"email", "message"}},
		{Action: "https://example.test/profile", Method: http.MethodPost, Fields: []string{"email", "csrf_token"}},
	}}
	scanner.scanDiscoveredCSRF("https://example.test", inventory)
	if got := len(scanner.Results.Items); got != 1 {
		t.Fatalf("expected one tokenless POST form finding, got %d", got)
	}
	if scanner.Results.Items[0].Confidence != "potential" {
		t.Fatalf("expected potential confidence, got %#v", scanner.Results.Items[0])
	}
}

func writePayloadFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "payloads.txt")

	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write payload file: %v", err)
	}

	return path
}
