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
