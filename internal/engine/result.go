package engine

import (
	"encoding/json"
	"fmt"
	"os"
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
	Target string       `json:"target"`
	Total  int          `json:"total"`
	Items  []ScanResult `json:"items"`
}

func NewResults() *Results {
	return &Results{
		Items: []ScanResult{},
	}
}

func (r *Results) Add(result ScanResult) {
	result.Timestamp = time.Now()
	r.Items = append(r.Items, result)
}

func (r *Results) Print() {
	for _, item := range r.Items {
		fmt.Printf("[%s] %s → %s\n", item.Severity, item.Name, item.Target)
	}
}

func (r *Results) SaveJSON(outputFile string) error {
	r.Total = len(r.Items)
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputFile, data, 0644)
}

// SaveHTML generates a nice HTML report
func (r *Results) SaveHTML(outputFile string) error {
	r.Total = len(r.Items)

	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
    <title>NeoScanner Report</title>
    <style>
        body { font-family: Arial; margin: 20px; background: #f4f4f4; }
        h1 { color: #1e3a8a; }
        table { width: 100%; border-collapse: collapse; background: white; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background: #1e3a8a; color: white; }
        .low { background: #fef3c7; }
        .medium { background: #fed7aa; }
        .high { background: #fecaca; }
    </style>
</head>
<body>
    <h1>NeoScanner Report</h1>
    <p><strong>Target:</strong> {{.Target}} | <strong>Findings:</strong> {{.Total}}</p>
    <table>
        <tr>
            <th>Severity</th>
            <th>Vulnerability</th>
            <th>Description</th>
            <th>Time</th>
        </tr>
        {{range .Items}}
        <tr class="{{.Severity}}">
            <td>{{.Severity}}</td>
            <td>{{.Name}}</td>
            <td>{{.Description}}</td>
            <td>{{.Timestamp.Format "2006-01-02 15:04:05"}}</td>
        </tr>
        {{end}}
    </table>
</body>
</html>`

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, r)
}
