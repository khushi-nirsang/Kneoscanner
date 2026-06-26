package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SaveSARIF writes the OASIS SARIF 2.1.0 subset understood by CI platforms
// and code-scanning dashboards.
func (r *Results) SaveSARIF(outputFile string) error {
	if err := ensureParentDir(outputFile); err != nil {
		return err
	}
	items := r.snapshot()
	sortResults(items)
	type rule struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		HelpURI          string `json:"helpUri,omitempty"`
		ShortDescription struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
	}
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations,omitempty"`
		Properties map[string]any `json:"properties,omitempty"`
	}
	rules := make([]rule, 0)
	results := make([]result, 0)
	seen := map[string]bool{}
	for _, item := range items {
		if !seen[item.TemplateID] {
			seen[item.TemplateID] = true
			current := rule{ID: item.TemplateID, Name: item.Name}
			current.ShortDescription.Text = item.Description
			if len(item.References) > 0 {
				current.HelpURI = item.References[0]
			}
			rules = append(rules, current)
		}
		current := result{RuleID: item.TemplateID, Level: sarifLevel(item.Severity), Properties: map[string]any{"finding_id": item.FindingID, "confidence": item.Confidence, "cwe": item.CWE, "cves": item.CVEs, "remediation": item.Remediation, "evidence": item.Evidence}}
		current.Message.Text = item.Name + ": " + item.Description
		var location struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		}
		location.PhysicalLocation.ArtifactLocation.URI = item.MatchedURL
		current.Locations = []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		}{location}
		results = append(results, current)
	}
	payload := map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "KneoScanner", "informationUri": "https://github.com/khushi-nirsang/neoscanner", "rules": rules}}, "results": results}}}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Clean(outputFile), data, 0644)
}
func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
