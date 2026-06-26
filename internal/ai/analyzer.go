package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/khushi-nirsang/neoscanner/internal/engine"
)

type Options struct {
	Enabled   bool
	Provider  string
	Endpoint  string
	Model     string
	APIKeyEnv string
	Timeout   time.Duration
}

func Analyze(ctx context.Context, options Options, findings []engine.ScanResult) *engine.AIAnalysis {
	if !options.Enabled {
		return nil
	}
	if options.Provider == "" {
		options.Provider = "local"
	}
	if options.APIKeyEnv == "" {
		options.APIKeyEnv = "OPENAI_API_KEY"
	}
	if options.Model == "" {
		options.Model = "gpt-4o-mini"
	}
	if options.Endpoint == "" {
		options.Endpoint = "https://api.openai.com/v1/chat/completions"
	}
	if options.Timeout <= 0 {
		options.Timeout = 20 * time.Second
	}

	local := localAnalysis(options, findings)
	if strings.EqualFold(options.Provider, "local") {
		return local
	}

	key := strings.TrimSpace(os.Getenv(options.APIKeyEnv))
	if key == "" {
		local.Provider = "local-fallback"
		local.Notes = append(local.Notes, fmt.Sprintf("No API key found in %s; used local analysis.", options.APIKeyEnv))
		return local
	}

	remote, err := openAICompatibleAnalysis(ctx, options, key, findings)
	if err != nil {
		local.Provider = "local-fallback"
		local.Error = err.Error()
		local.Notes = append(local.Notes, "Remote AI analysis failed; used local analysis.")
		return local
	}
	return remote
}

func localAnalysis(options Options, findings []engine.ScanResult) *engine.AIAnalysis {
	counts := severityCounts(findings)
	risk := riskLevel(counts)
	priorities := priorityFindings(findings, 5)
	steps := recommendedSteps(findings, counts)
	summary := fmt.Sprintf("KneoScanner found %d issue(s): %d critical, %d high, %d medium, %d low, and %d informational. Overall risk is %s.",
		len(findings), counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"], risk)
	if len(findings) == 0 {
		summary = "KneoScanner did not find reportable issues in this run. Continue with authenticated testing and active profiles when authorized."
	}
	return &engine.AIAnalysis{
		Enabled:          true,
		Provider:         "local",
		Model:            options.Model,
		GeneratedAt:      time.Now(),
		ExecutiveSummary: summary,
		RiskLevel:        risk,
		PriorityFindings: priorities,
		RecommendedSteps: steps,
	}
}

func openAICompatibleAnalysis(ctx context.Context, options Options, apiKey string, findings []engine.ScanResult) (*engine.AIAnalysis, error) {
	payload := map[string]any{
		"model": options.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a concise cybersecurity analyst. Return strict JSON with keys executive_summary, risk_level, priority_findings, recommended_steps, notes. Do not include secrets or raw HTTP bodies."},
			{"role": "user", "content": buildPrompt(findings)},
		},
		"temperature": 0.2,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, options.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error any `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("AI API returned status %d", resp.StatusCode)
	}
	if len(decoded.Choices) == 0 {
		return nil, fmt.Errorf("AI API returned no choices")
	}
	var analysis engine.AIAnalysis
	if err := json.Unmarshal([]byte(extractJSON(decoded.Choices[0].Message.Content)), &analysis); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}
	analysis.Enabled = true
	analysis.Provider = options.Provider
	analysis.Model = options.Model
	analysis.GeneratedAt = time.Now()
	if analysis.RiskLevel == "" {
		analysis.RiskLevel = riskLevel(severityCounts(findings))
	}
	return &analysis, nil
}

func buildPrompt(findings []engine.ScanResult) string {
	type compactFinding struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Confidence  string   `json:"confidence,omitempty"`
		URL         string   `json:"url"`
		Parameter   string   `json:"parameter,omitempty"`
		Evidence    []string `json:"evidence,omitempty"`
		Remediation string   `json:"remediation,omitempty"`
	}
	compact := make([]compactFinding, 0, min(len(findings), 30))
	for i, finding := range findings {
		if i >= 30 {
			break
		}
		compact = append(compact, compactFinding{
			Name:        finding.Name,
			Severity:    finding.Severity,
			Confidence:  finding.Confidence,
			URL:         finding.MatchedURL,
			Parameter:   finding.Parameter,
			Evidence:    finding.Evidence,
			Remediation: finding.Remediation,
		})
	}
	data, _ := json.Marshal(compact)
	return "Analyze these KneoScanner findings and produce analyst-ready remediation guidance as JSON only:\n" + string(data)
}

func severityCounts(findings []engine.ScanResult) map[string]int {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, finding := range findings {
		counts[strings.ToLower(finding.Severity)]++
	}
	return counts
}

func riskLevel(counts map[string]int) string {
	switch {
	case counts["critical"] > 0:
		return "critical"
	case counts["high"] > 0:
		return "high"
	case counts["medium"] > 0:
		return "medium"
	case counts["low"] > 0:
		return "low"
	default:
		return "informational"
	}
}

func priorityFindings(findings []engine.ScanResult, limit int) []string {
	items := append([]engine.ScanResult(nil), findings...)
	sort.SliceStable(items, func(i, j int) bool {
		return severityRank(items[i].Severity) > severityRank(items[j].Severity)
	})
	out := []string{}
	for _, item := range items {
		if len(out) >= limit {
			break
		}
		out = append(out, fmt.Sprintf("%s [%s] at %s", item.Name, strings.ToUpper(item.Severity), item.MatchedURL))
	}
	return out
}

func recommendedSteps(findings []engine.ScanResult, counts map[string]int) []string {
	steps := []string{}
	if counts["critical"]+counts["high"] > 0 {
		steps = append(steps, "Fix critical and high severity findings first, then rerun the same scan profile to confirm remediation.")
	}
	if hasTemplate(findings, "sql-injection") {
		steps = append(steps, "Review database access paths and enforce parameterized queries for all affected inputs.")
	}
	if hasTemplate(findings, "xss-probe") {
		steps = append(steps, "Apply context-aware output encoding and validate Content-Security-Policy coverage.")
	}
	if hasTemplate(findings, "csrf-discovered-form") || hasTemplate(findings, "csrf-detection") {
		steps = append(steps, "Add server-validated CSRF tokens and SameSite cookie protections to state-changing forms.")
	}
	if len(steps) == 0 {
		steps = append(steps, "Review discovered endpoints, add authentication context, and run an authorized active scan for deeper validation.")
	}
	return steps
}

func hasTemplate(findings []engine.ScanResult, id string) bool {
	for _, finding := range findings {
		if finding.TemplateID == id {
			return true
		}
	}
	return false
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func extractJSON(value string) string {
	value = strings.TrimSpace(value)
	start := strings.Index(value, "{")
	end := strings.LastIndex(value, "}")
	if start >= 0 && end > start {
		return value[start : end+1]
	}
	return value
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
