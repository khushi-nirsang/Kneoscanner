package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveSARIFWritesFindingMetadata(t *testing.T) {
	results := NewResults()
	results.Add(ScanResult{TemplateID: "xss-probe", Name: "Reflected XSS", Severity: "high", Description: "payload reflected", MatchedURL: "https://app.test/search?q=x", FindingID: "neo-test", Confidence: "firm", CWE: []string{"CWE-79"}})
	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := results.SaveSARIF(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"version": "2.1.0"`, `"ruleId": "xss-probe"`, `"finding_id": "neo-test"`, `"level": "error"`} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("SARIF missing %s: %s", expected, data)
		}
	}
}
