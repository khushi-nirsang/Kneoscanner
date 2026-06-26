package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSavePDFCreatesDetailedReport(t *testing.T) {
	results := NewResults()
	results.Add(ScanResult{Name: "Reflected XSS", Severity: "medium", Target: "https://example.test", MatchedURL: "https://example.test/search?q=x", Method: "GET", Parameter: "q", Payload: "<script>alert(1)</script>", Evidence: []string{"response reflected the injected payload"}})
	path := filepath.Join(t.TempDir(), "results.pdf")
	if err := results.SavePDF(path); err != nil {
		t.Fatalf("save PDF: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}
	if !strings.HasPrefix(string(data), "%PDF-1.4") || !strings.Contains(string(data), "Remediation") {
		t.Fatal("expected a detailed, valid PDF document")
	}
}
