package templates

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplateAcceptsHeaderList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "headers-list.yaml")
	data := []byte(`id: header-list
info:
  name: Header List
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      - "X-Test: yes"
      - "Host: example.com"
    matchers:
      - type: word
        part: body
        words:
          - ok
`)

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	tmpl, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("load template: %v", err)
	}

	if got := tmpl.Requests[0].Headers["X-Test"]; got != "yes" {
		t.Fatalf("expected X-Test header yes, got %q", got)
	}
	if got := tmpl.Requests[0].Headers["Host"]; got != "example.com" {
		t.Fatalf("expected Host header example.com, got %q", got)
	}
}

func TestValidateTemplateRejectsRequestWithoutMatchers(t *testing.T) {
	tmpl := Template{
		ID: "missing-matchers",
		Info: Info{
			Name: "Missing Matchers",
		},
		Requests: []Request{
			{
				Method: "GET",
				Path:   []string{"{{BaseURL}}"},
			},
		},
	}

	if err := ValidateTemplate(tmpl); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateTemplateRejectsInvalidQualityMetadata(t *testing.T) {
	base := Template{ID: "quality", Info: Info{Name: "Quality", Severity: "medium"}, Requests: []Request{{Method: "GET", Path: []string{"{{BaseURL}}"}, Matchers: []Matcher{{Type: "status", Status: []int{200}}}}}}
	base.Info.Confidence = "certain"
	if err := ValidateTemplate(base); err == nil {
		t.Fatal("expected invalid confidence to be rejected")
	}
	base.Info.Confidence = "firm"
	base.Info.CVSSScore = 10.1
	if err := ValidateTemplate(base); err == nil {
		t.Fatal("expected invalid CVSS score to be rejected")
	}
	base.Info.CVSSScore = 0
	base.Info.Risk = "unsafe"
	if err := ValidateTemplate(base); err == nil {
		t.Fatal("expected invalid risk to be rejected")
	}
}

func TestValidateTemplateRejectsInvalidRegex(t *testing.T) {
	tmpl := Template{
		ID:   "broken-regex",
		Info: Info{Name: "Broken", Severity: "low"},
		Requests: []Request{{
			Method:   "GET",
			Path:     []string{"{{BaseURL}}"},
			Matchers: []Matcher{{Type: "regex", Regex: []string{"("}}},
		}},
	}
	if err := ValidateTemplate(tmpl); err == nil {
		t.Fatal("expected invalid regex to be rejected before scanning")
	}
}
