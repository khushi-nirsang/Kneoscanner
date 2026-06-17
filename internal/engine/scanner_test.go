package engine

import (
	"net/http"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/templates"
	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

func TestBuildRequestURLRendersBaseURL(t *testing.T) {

	got := buildRequestURL(
		"https://example.com/root",
		"{{BaseURL}}/.git/HEAD",
	)

	want := "https://example.com/root/.git/HEAD"

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

	if !scanner.matchResponse(resp, matcher) {
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

	if !scanner.matchResponse(resp, matcher) {
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

	if scanner.matchMatchers(resp, matchers, "and") {
		t.Fatal("expected AND condition to fail")
	}

	if !scanner.matchMatchers(resp, matchers, "or") {
		t.Fatal("expected OR condition to succeed")
	}
}