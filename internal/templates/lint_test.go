package templates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLintDirectoryReportsInvalidTemplates(t *testing.T) {
	dir := t.TempDir()
	valid := `id: valid
info:
  name: Valid
  severity: low
requests:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers: [{type: status, status: [200]}]
`
	invalid := `id: invalid
info: {name: Invalid, severity: low}
requests: [{method: GET, path: ["{{BaseURL}}"], matchers: [{type: regex, regex: ["("]}]}]
`
	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "invalid.yaml"), []byte(invalid), 0644); err != nil {
		t.Fatal(err)
	}
	report, err := LintDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Checked != 2 || report.Valid != 1 || len(report.Issues) != 1 {
		t.Fatalf("unexpected lint report: %#v", report)
	}
}

func TestWriteManifestUsesStableTemplateHashes(t *testing.T) {
	dir := t.TempDir()
	content := `id: valid
info: {name: Valid, severity: low}
requests: [{method: GET, path: ["{{BaseURL}}"], matchers: [{type: status, status: [200]}]}]
`
	if err := os.WriteFile(filepath.Join(dir, "valid.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "manifest.json")
	manifest, err := WriteManifest(dir, output)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Templates) != 1 || manifest.Templates[0].Path != "valid.yaml" || len(manifest.Templates[0].SHA256) != 64 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

func TestVerifyManifestDetectsModifiedTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.yaml")
	content := `id: valid
info: {name: Valid, severity: low}
requests: [{method: GET, path: ["{{BaseURL}}"], matchers: [{type: status, status: [200]}]}]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "approved.json")
	if _, err := WriteManifest(dir, manifest); err != nil {
		t.Fatal(err)
	}
	issues, err := VerifyManifest(dir, manifest)
	if err != nil || len(issues) != 0 {
		t.Fatalf("expected matching manifest: issues=%v err=%v", issues, err)
	}
	if err := os.WriteFile(path, []byte(content+"\n# changed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	issues, err = VerifyManifest(dir, manifest)
	if err != nil || len(issues) != 1 || issues[0] != "modified template: valid.yaml" {
		t.Fatalf("expected modification issue: %v err=%v", issues, err)
	}
}
