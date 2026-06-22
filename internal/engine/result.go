package engine

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Target      string    `json:"target"`
	TemplateID  string    `json:"template_id"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Matched     bool      `json:"matched"`
	Description string    `json:"description"`
	MatchedURL  string    `json:"matched_url"`
	Method      string    `json:"method"`
	StatusCode  int       `json:"status_code"`
	Timestamp   time.Time `json:"timestamp"`
}

type Results struct {
	Items []ScanResult `json:"items"`

	mu   sync.Mutex
	seen map[string]struct{}
}

func NewResults() *Results {
	return &Results{
		Items: make([]ScanResult, 0),
		seen:  make(map[string]struct{}),
	}
}

func (r *Results) Add(result ScanResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf(
		"%s|%s|%s|%s",
		result.Target,
		result.TemplateID,
		result.Method,
		result.MatchedURL,
	)

	if _, exists := r.seen[key]; exists {
		return
	}

	r.seen[key] = struct{}{}

	result.Timestamp = time.Now()

	r.Items = append(r.Items, result)
}

func (r *Results) Print() {
	items := r.snapshot()

	sortResults(items)

	for _, item := range items {
		fmt.Printf(
			"[%s] %s -> %s\n",
			item.Severity,
			item.Name,
			item.MatchedURL,
		)
	}
}

func (r *Results) SaveJSON(outputFile string) error {

	items := r.snapshot()
	sortResults(items)

	payload := struct {
		GeneratedAt time.Time    `json:"generated_at"`
		Total       int          `json:"total"`
		Items       []ScanResult `json:"items"`
	}{
		GeneratedAt: time.Now(),
		Total:       len(items),
		Items:       items,
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
	}{
		GeneratedAt: time.Now().Format(time.RFC1123),
		Total:       len(items),
		Stats:       stats,
		Items:       items,
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
<title>NeoScanner Report</title>

<style>

body{
font-family:Arial,sans-serif;
background:#f4f4f4;
margin:20px;
}

h1{
color:#1e3a8a;
}

.summary{
display:flex;
gap:15px;
margin-bottom:20px;
}

.card{
padding:12px;
background:white;
border-radius:8px;
box-shadow:0 0 5px rgba(0,0,0,.1);
}

table{
width:100%;
border-collapse:collapse;
background:white;
}

th,td{
padding:10px;
border:1px solid #ddd;
text-align:left;
}

th{
background:#1e3a8a;
color:white;
}

.info{background:#e0f2fe;}
.low{background:#fef3c7;}
.medium{background:#fed7aa;}
.high{background:#fecaca;}
.critical{background:#fca5a5;}

</style>

</head>

<body>

<h1>NeoScanner Report</h1>

<p>Generated: {{.GeneratedAt}}</p>

<div class="summary">

<div class="card">Total: {{.Total}}</div>
<div class="card">Critical: {{.Stats.Critical}}</div>
<div class="card">High: {{.Stats.High}}</div>
<div class="card">Medium: {{.Stats.Medium}}</div>
<div class="card">Low: {{.Stats.Low}}</div>
<div class="card">Info: {{.Stats.Info}}</div>

</div>

<table>

<tr>
<th>Target</th>
<th>URL</th>
<th>Method</th>
<th>Status</th>
<th>Severity</th>
<th>Name</th>
<th>Description</th>
</tr>

{{range .Items}}

<tr class="{{.Severity}}">
<td>{{.Target}}</td>
<td>{{.MatchedURL}}</td>
<td>{{.Method}}</td>
<td>{{.StatusCode}}</td>
<td>{{.Severity}}</td>
<td>{{.Name}}</td>
<td>{{.Description}}</td>
</tr>

{{end}}

</table>

</body>
</html>
`
