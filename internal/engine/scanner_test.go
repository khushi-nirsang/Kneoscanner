package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

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

	if got := len(scanner.Results.Items); got != 2 {
		t.Fatalf("expected 2 deduplicated URL findings, got %d", got)
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

func writePayloadFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "payloads.txt")

	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write payload file: %v", err)
	}

	return path
}
