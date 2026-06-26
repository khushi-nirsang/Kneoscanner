package ai

import (
	"context"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/engine"
)

func TestAnalyzeLocalBuildsRiskSummary(t *testing.T) {
	analysis := Analyze(context.Background(), Options{Enabled: true, Provider: "local"}, []engine.ScanResult{
		{Name: "SQL Injection", Severity: "critical", MatchedURL: "https://example.test/?id=1", TemplateID: "sql-injection"},
		{Name: "Reflected XSS", Severity: "high", MatchedURL: "https://example.test/?q=x", TemplateID: "xss-probe"},
	})
	if analysis == nil {
		t.Fatal("expected analysis")
	}
	if analysis.RiskLevel != "critical" {
		t.Fatalf("expected critical risk, got %q", analysis.RiskLevel)
	}
	if len(analysis.PriorityFindings) == 0 || len(analysis.RecommendedSteps) == 0 {
		t.Fatalf("expected priorities and steps, got %#v", analysis)
	}
}

func TestAnalyzeDisabledReturnsNil(t *testing.T) {
	if got := Analyze(context.Background(), Options{}, nil); got != nil {
		t.Fatalf("expected nil analysis when disabled, got %#v", got)
	}
}
