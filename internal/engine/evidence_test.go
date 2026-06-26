package engine

import (
	"net/http"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/templates"
	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

func TestTranscriptRedactsCredentialsAndBoundsBody(t *testing.T) {
	scanner := NewScanner(1, 1)
	scanner.ConfigureEvidence(12, true)
	response := &utils.Response{Response: &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Set-Cookie": {"session=secret"}}, Request: &http.Request{Header: http.Header{"Authorization": {"Bearer secret"}}}}, BodyContent: "token=secret-value&ok=true", RequestedURL: "https://example.test", FinalURL: "https://example.test", BodySize: 26}

	request := scanner.requestTranscript(http.MethodPost, "https://example.test/login", "username=alice&password=hunter2", response)
	if request.Headers["Authorization"][0] != "[REDACTED]" || request.Body == "username=alice&password=hunter2" || !request.Redacted {
		t.Fatalf("request transcript was not redacted: %#v", request)
	}
	result := scanner.transcript(http.MethodPost, "https://example.test/login", "", response)
	if result.Headers["Set-Cookie"][0] != "[REDACTED]" || len(result.Body) > 12 || !result.Truncated {
		t.Fatalf("response transcript was not bounded/redacted: %#v", result)
	}
}

func TestTemplateResultPreservesFindingMetadata(t *testing.T) {
	scanner := NewScanner(1, 1)
	tmpl := &templates.Template{ID: "example", Info: templates.Info{Name: "Example", Author: "neo", Severity: "high", Confidence: "firm", CWE: []string{"CWE-79"}, CVSSScore: 8.2, CVSSVector: "CVSS:3.1/AV:N", Impact: "Script execution", CVEs: []string{"CVE-2025-0001"}, References: []string{"https://example.test/advisory"}, Remediation: "Encode output."}}
	result := scanner.templateResult(tmpl, "https://example.test", http.MethodGet, "https://example.test/?q=x", "q", "x", "", nil, "")
	result = enrichResult(result)
	if result.Confidence != "firm" || result.CWE[0] != "CWE-79" || result.CVEs[0] != "CVE-2025-0001" || result.Remediation != "Encode output." || result.FindingID == "" || result.Fingerprint == "" {
		t.Fatalf("template metadata was lost: %#v", result)
	}
}

func TestTemplateResultIncludesTechnologyFingerprint(t *testing.T) {
	scanner := NewScanner(1, 1)
	response := &utils.Response{Response: &http.Response{Header: http.Header{"Server": {"nginx"}, "X-Powered-By": {"Express"}}}, BodyContent: "<script src=\"/_next/static/app.js\"></script>"}
	result := scanner.templateResult(&templates.Template{ID: "technology", Info: templates.Info{Name: "Technology", Severity: "info"}}, "https://example.test", http.MethodGet, "https://example.test", "", "", "", response, "")
	if len(result.Technologies) == 0 || result.Technologies[0] != "nginx" {
		t.Fatalf("expected technology fingerprint, got %#v", result.Technologies)
	}
}
