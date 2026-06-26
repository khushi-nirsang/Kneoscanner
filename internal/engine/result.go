package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/khushi-nirsang/neoscanner/internal/discovery"
)

type ScanResult struct {
	FindingID      string          `json:"finding_id"`
	Fingerprint    string          `json:"fingerprint"`
	Target         string          `json:"target"`
	TemplateID     string          `json:"template_id"`
	TemplateAuthor string          `json:"template_author,omitempty"`
	Name           string          `json:"name"`
	Severity       string          `json:"severity"`
	OWASPCategory  string          `json:"owasp_category,omitempty"`
	Confidence     string          `json:"confidence,omitempty"`
	CWE            []string        `json:"cwe,omitempty"`
	CVSSScore      float64         `json:"cvss_score,omitempty"`
	CVSSVector     string          `json:"cvss_vector,omitempty"`
	Impact         string          `json:"impact,omitempty"`
	Technologies   []string        `json:"technologies,omitempty"`
	Matched        bool            `json:"matched"`
	Description    string          `json:"description"`
	MatchedURL     string          `json:"matched_url"`
	FinalURL       string          `json:"final_url"`
	Method         string          `json:"method"`
	StatusCode     int             `json:"status_code"`
	Payload        string          `json:"payload,omitempty"`
	Parameter      string          `json:"parameter,omitempty"`
	Evidence       []string        `json:"evidence,omitempty"`
	CVEs           []string        `json:"cves,omitempty"`
	References     []string        `json:"references,omitempty"`
	Remediation    string          `json:"remediation,omitempty"`
	BodySize       int64           `json:"body_size"`
	Truncated      bool            `json:"truncated"`
	Attempts       int             `json:"attempts"`
	Request        *HTTPTranscript `json:"request,omitempty"`
	Response       *HTTPTranscript `json:"response,omitempty"`
	Baseline       *HTTPTranscript `json:"baseline,omitempty"`
	Timestamp      time.Time       `json:"timestamp"`
}

type AIAnalysis struct {
	Enabled          bool      `json:"enabled"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model,omitempty"`
	GeneratedAt      time.Time `json:"generated_at"`
	ExecutiveSummary string    `json:"executive_summary"`
	RiskLevel        string    `json:"risk_level"`
	PriorityFindings []string  `json:"priority_findings,omitempty"`
	RecommendedSteps []string  `json:"recommended_steps,omitempty"`
	Notes            []string  `json:"notes,omitempty"`
	Error            string    `json:"error,omitempty"`
}

func (r *Results) SavePDF(outputFile string) error {
	items := r.snapshot()
	sortResults(items)
	if err := ensureParentDir(outputFile); err != nil {
		return err
	}
	return writePDFReport(outputFile, items)
}

type Results struct {
	Items       []ScanResult          `json:"items"`
	Discoveries []discovery.Inventory `json:"discoveries"`
	AIAnalysis  *AIAnalysis           `json:"ai_analysis,omitempty"`

	mu   sync.Mutex
	seen map[string]int
}

func NewResults() *Results {
	return &Results{
		Items:       make([]ScanResult, 0),
		Discoveries: make([]discovery.Inventory, 0),
		seen:        make(map[string]int),
	}
}

func (r *Results) SetAIAnalysis(analysis *AIAnalysis) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.AIAnalysis = analysis
}

func (r *Results) AddDiscovery(inventory discovery.Inventory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index, existing := range r.Discoveries {
		if existing.Target == inventory.Target {
			r.Discoveries[index] = inventory
			return
		}
	}
	r.Discoveries = append(r.Discoveries, inventory)
}

// Add stores one finding per template, endpoint, HTTP method, and parameter
// set. Payload variants are evidence for the same issue, not separate issues.
// It returns true only when a new finding was stored.
func (r *Results) Add(result ScanResult) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	result = enrichResult(result)

	key := fmt.Sprintf(
		"%s|%s|%s|%s",
		result.Target,
		result.TemplateID,
		result.Method,
		findingLocation(result.MatchedURL),
	)

	if index, exists := r.seen[key]; exists {
		r.Items[index] = mergeFindingEvidence(r.Items[index], result)
		return false
	}

	r.seen[key] = len(r.Items)

	result.Timestamp = time.Now()

	r.Items = append(r.Items, result)
	return true
}

func enrichResult(result ScanResult) ScanResult {
	if result.Confidence == "" {
		result.Confidence = "potential"
	}
	if result.Remediation == "" {
		result.Remediation = remediationFor(result)
	}
	if len(result.References) == 0 {
		switch result.TemplateID {
		case "xss-probe":
			result.References = []string{"https://owasp.org/www-community/attacks/xss/"}
		case "authentication-bypass", "weak-authentication":
			result.References = []string{"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"}
		case "csrf-discovered-form", "csrf-detection":
			result.References = []string{"https://owasp.org/www-community/attacks/csrf"}
		case "sql-injection":
			result.References = []string{"https://owasp.org/www-community/attacks/SQL_Injection"}
		case "ssrf-probe":
			result.References = []string{"https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"}
		default:
			result.References = []string{"https://owasp.org/Top10/"}
		}
	}
	if result.Fingerprint == "" {
		result.Fingerprint = findingFingerprint(result)
	}
	if result.FindingID == "" {
		result.FindingID = result.Fingerprint
	}
	return result
}

func findingFingerprint(result ScanResult) string {
	location := findingLocation(result.MatchedURL)
	canonical := strings.Join([]string{strings.ToLower(result.TemplateID), strings.ToUpper(result.Method), strings.ToLower(result.Parameter), location}, "|")
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("neo-%x", sum[:12])
}

func mergeFindingEvidence(existing, incoming ScanResult) ScanResult {
	existing.Evidence = uniqueStrings(append(existing.Evidence, incoming.Evidence...))
	if existing.Payload == "" {
		existing.Payload = incoming.Payload
	}
	if existing.Request == nil {
		existing.Request = incoming.Request
	}
	if existing.Response == nil {
		existing.Response = incoming.Response
	}
	if existing.Baseline == nil {
		existing.Baseline = incoming.Baseline
	}
	return existing
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// findingLocation removes query values while preserving parameter names. This
// collapses multiple successful payloads sent to the same input, while keeping
// separate inputs (for example ?id and ?search) as distinct findings.
func findingLocation(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := parsed.Query()
	if len(query) == 0 {
		return parsed.String()
	}
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parsed.RawQuery = strings.Join(keys, "&")
	return parsed.String()
}

func (r *Results) Print() {
	items := r.snapshot()

	sortResults(items)

	for _, item := range items {
		if item.Payload != "" {
			fmt.Printf(
				"[%s] %s -> %s (payload: %s)\n",
				item.Severity,
				item.Name,
				item.MatchedURL,
				item.Payload,
			)
		} else {
			fmt.Printf(
				"[%s] %s -> %s\n",
				item.Severity,
				item.Name,
				item.MatchedURL,
			)
		}
	}
}

func (r *Results) SaveJSON(outputFile string) error {

	items := r.snapshot()
	sortResults(items)

	payload := struct {
		GeneratedAt time.Time             `json:"generated_at"`
		Total       int                   `json:"total"`
		Items       []ScanResult          `json:"items"`
		Discoveries []discovery.Inventory `json:"discoveries"`
		AIAnalysis  *AIAnalysis           `json:"ai_analysis,omitempty"`
	}{
		GeneratedAt: time.Now(),
		Total:       len(items),
		Items:       items,
		Discoveries: r.discoverySnapshot(),
		AIAnalysis:  r.aiSnapshot(),
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}

	if err := ensureParentDir(outputFile); err != nil {
		return err
	}

	return os.WriteFile(outputFile, data, 0644)
}

func (r *Results) SaveHTML(outputFile string) error {

	items := r.snapshot()
	sortResults(items)

	stats := buildStatistics(items)

	if err := ensureParentDir(outputFile); err != nil {
		return err
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	tmpl := template.Must(template.New("report").Parse(htmlReport))

	return tmpl.Execute(f, struct {
		GeneratedAt string
		Total       int
		Stats       SeverityStats
		Items       []ScanResult
		Discoveries []discovery.Inventory
		AIAnalysis  *AIAnalysis
	}{
		GeneratedAt: time.Now().Format(time.RFC1123),
		Total:       len(items),
		Stats:       stats,
		Items:       items,
		Discoveries: r.discoverySnapshot(),
		AIAnalysis:  r.aiSnapshot(),
	})
}

func (r *Results) FilterBySeverity(severity string) {

	if severity == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	required := getSeverityLevel(severity)

	filtered := make([]ScanResult, 0)

	for _, item := range r.Items {

		if getSeverityLevel(item.Severity) >= required {
			filtered = append(filtered, item)
		}
	}

	r.Items = filtered
}

func (r *Results) snapshot() []ScanResult {

	r.mu.Lock()
	defer r.mu.Unlock()

	items := make([]ScanResult, len(r.Items))
	copy(items, r.Items)

	return items
}

func (r *Results) discoverySnapshot() []discovery.Inventory {
	r.mu.Lock()
	defer r.mu.Unlock()
	items := make([]discovery.Inventory, len(r.Discoveries))
	copy(items, r.Discoveries)
	return items
}

func (r *Results) aiSnapshot() *AIAnalysis {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.AIAnalysis
}

type SeverityStats struct {
	Info     int
	Low      int
	Medium   int
	High     int
	Critical int
}

func buildStatistics(items []ScanResult) SeverityStats {

	var stats SeverityStats

	for _, item := range items {

		switch strings.ToLower(item.Severity) {

		case "info":
			stats.Info++

		case "low":
			stats.Low++

		case "medium":
			stats.Medium++

		case "high":
			stats.High++

		case "critical":
			stats.Critical++
		}
	}

	return stats
}

func sortResults(items []ScanResult) {

	sort.SliceStable(items, func(i, j int) bool {

		left := getSeverityLevel(items[i].Severity)
		right := getSeverityLevel(items[j].Severity)

		if left != right {
			return left > right
		}

		return items[i].Name < items[j].Name
	})
}

func ensureParentDir(filePath string) error {

	dir := filepath.Dir(filePath)

	if dir == "." || dir == "" {
		return nil
	}

	return os.MkdirAll(dir, 0755)
}

func getSeverityLevel(sev string) int {

	switch strings.ToLower(sev) {

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

const htmlReport = `
<!DOCTYPE html>
<html>
<head>
<title>KneoScanner Report</title>

<style>
:root{color-scheme:dark;--bg:#0b1220;--surface:#121c2e;--surface2:#17243a;--text:#e5edf8;--muted:#9badc5;--line:#293a55;--blue:#6ea8fe}
*{box-sizing:border-box} body{margin:0;padding:36px;font-family:Inter,Segoe UI,Arial,sans-serif;background:linear-gradient(145deg,#09111f,#101b2e);color:var(--text)}
h1{margin:0;font-size:30px;letter-spacing:-.5px} h2{margin:34px 0 12px;font-size:18px} p{color:var(--muted)}
.summary{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:12px;margin:26px 0}.card{padding:16px;border:1px solid var(--line);border-radius:12px;background:var(--surface);font-weight:600;box-shadow:0 12px 28px rgba(0,0,0,.18)}
table{width:100%;border-collapse:separate;border-spacing:0;background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden;box-shadow:0 12px 28px rgba(0,0,0,.16)}
th,td{padding:13px 14px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;font-size:13px}th{background:var(--surface2);color:#cfe0ff;font-size:11px;letter-spacing:.06em;text-transform:uppercase;position:sticky;top:0}tr:last-child td{border-bottom:0}td:nth-child(2),td:nth-child(3){word-break:break-all;color:#c7d7ef}
.info{background:rgba(56,189,248,.08)}.low{background:rgba(250,204,21,.08)}.medium{background:rgba(251,146,60,.10)}.high{background:rgba(248,113,113,.12)}.critical{background:rgba(244,63,94,.18)}
@media(max-width:900px){body{padding:20px}.summary{grid-template-columns:repeat(2,1fr)}table{display:block;overflow-x:auto;white-space:nowrap}}

</style>

</head>

<body>

<h1>KneoScanner Report</h1>

<p>Generated: {{.GeneratedAt}}</p>

<div class="summary">

<div class="card">Total: {{.Total}}</div>
<div class="card">Critical: {{.Stats.Critical}}</div>
<div class="card">High: {{.Stats.High}}</div>
<div class="card">Medium: {{.Stats.Medium}}</div>
<div class="card">Low: {{.Stats.Low}}</div>
<div class="card">Info: {{.Stats.Info}}</div>

</div>

{{if .AIAnalysis}}
<h2>AI Analyst Summary</h2>
<table>
<tr><th>Provider</th><th>Risk Level</th><th>Executive Summary</th></tr>
<tr><td>{{.AIAnalysis.Provider}}{{if .AIAnalysis.Model}} / {{.AIAnalysis.Model}}{{end}}</td><td>{{.AIAnalysis.RiskLevel}}</td><td>{{.AIAnalysis.ExecutiveSummary}}</td></tr>
</table>
{{if .AIAnalysis.PriorityFindings}}
<h2>AI Priorities</h2>
<table><tr><th>Priority Finding</th></tr>{{range .AIAnalysis.PriorityFindings}}<tr><td>{{.}}</td></tr>{{end}}</table>
{{end}}
{{if .AIAnalysis.RecommendedSteps}}
<h2>AI Recommended Steps</h2>
<table><tr><th>Next Step</th></tr>{{range .AIAnalysis.RecommendedSteps}}<tr><td>{{.}}</td></tr>{{end}}</table>
{{end}}
{{end}}

{{if .Discoveries}}
<h2>Application Discovery</h2>
<table>
<tr><th>Target</th><th>Pages</th><th>Endpoints</th><th>Forms</th><th>Scripts</th><th>API Routes</th></tr>
{{range .Discoveries}}
<tr><td>{{.Target}}</td><td>{{len .Pages}}</td><td>{{len .Endpoints}}</td><td>{{len .Forms}}</td><td>{{len .Scripts}}</td><td>{{len .APIs}}</td></tr>
{{end}}
</table>
{{end}}

<table>

<tr>
<th>Target</th>
<th>URL</th>
<th>Final URL</th>
<th>Method</th>
<th>Status</th>
<th>Attempts</th>
<th>Payload</th>
<th>Confidence</th>
<th>Proof</th>
<th>Remediation</th>
<th>Severity</th>
<th>Name</th>
<th>Description</th>
</tr>

{{range .Items}}

<tr class="{{.Severity}}">
<td>{{.Target}}</td>
<td>{{.MatchedURL}}</td>
<td>{{.FinalURL}}</td>
<td>{{.Method}}</td>
<td>{{.StatusCode}}</td>
<td>{{.Attempts}}</td>
<td>{{.Payload}}</td>
<td>{{.Confidence}}</td>
<td>{{range .Evidence}}{{.}}<br>{{end}}</td>
<td>{{.Remediation}}<br>{{range .References}}<a href="{{.}}">Reference</a><br>{{end}}</td>
<td>{{.Severity}}</td>
<td>{{.Name}}</td>
<td>{{.Description}}</td>
</tr>

{{end}}

</table>

</body>
</html>
`
