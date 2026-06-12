package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"
)

type ScanResult struct {
	Target      string    `json:"target"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Matched     bool      `json:"matched"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

type Results struct {
	Items []ScanResult `json:"items"`
	mu    sync.Mutex
}

func NewResults() *Results {
	return &Results{
		Items: []ScanResult{},
	}
}

func (r *Results) Add(result ScanResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result.Timestamp = time.Now()
	r.Items = append(r.Items, result)
}

func (r *Results) Print() {
	for _, item := range r.Items {
		fmt.Printf("[%s] %s → %s\n", item.Severity, item.Name, item.Target)
	}
}

func (r *Results) SaveJSON(outputFile string) error {
	r.mu.Lock()
	data, err := json.MarshalIndent(struct {
		Total int          `json:"total"`
		Items []ScanResult `json:"items"`
	}{
		Total: len(r.Items),
		Items: r.Items,
	}, "", "  ")
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return os.WriteFile(outputFile, data, 0644)
}

func (r *Results) SaveHTML(outputFile string) error {
	r.mu.Lock()
	total := len(r.Items)
	r.mu.Unlock()

	htmlTemplate := `<!DOCTYPE html>
<html>
<head><title>NeoScanner Report</title>
<style>
body{font-family:Arial;margin:20px;background:#f4f4f4}
h1{color:#1e3a8a}
table{width:100%;border-collapse:collapse;background:white}
th,td{padding:12px;border:1px solid #ddd;text-align:left}
th{background:#1e3a8a;color:white}
.low{background:#fef3c7}
.medium{background:#fed7aa}
.high{background:#fecaca}
.critical{background:#fca5a5}
</style>
</head>
<body>
<h1>NeoScanner Report</h1>
<p>Total Findings: {{.Total}}</p>
<table>
<tr><th>Target</th><th>Severity</th><th>Vulnerability</th><th>Description</th></tr>
{{range .Items}}
<tr class="{{.Severity}}"><td>{{.Target}}</td><td>{{.Severity}}</td><td>{{.Name}}</td><td>{{.Description}}</td></tr>
{{end}}
</table>
</body>
</html>`

	tmpl, _ := template.New("report").Parse(htmlTemplate)
	f, _ := os.Create(outputFile)
	defer f.Close()
	tmpl.Execute(f, struct{ Total int }{Total: total})
	return nil
}

func (r *Results) FilterBySeverity(severity string) {
	if severity == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	severityLevel := getSeverityLevel(severity)
	var filtered []ScanResult

	for _, item := range r.Items {
		if getSeverityLevel(item.Severity) >= severityLevel {
			filtered = append(filtered, item)
		}
	}
	r.Items = filtered
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