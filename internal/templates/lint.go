package templates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type LintReport struct {
	Checked int
	Valid   int
	Issues  []string
}

// LintDirectory validates every YAML template before it reaches a scan job.
func LintDirectory(dir string) (LintReport, error) {
	report := LintReport{}
	if _, err := os.Stat(dir); err != nil {
		return report, fmt.Errorf("template directory not found: %s", dir)
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") && !strings.HasSuffix(strings.ToLower(info.Name()), ".yml") {
			return nil
		}
		report.Checked++
		tmpl, err := LoadTemplate(path)
		if err == nil {
			err = ValidateTemplate(*tmpl)
		}
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		report.Valid++
		return nil
	})
	return report, err
}

type Manifest struct {
	GeneratedAt string          `json:"generated_at"`
	Templates   []ManifestEntry `json:"templates"`
}
type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// VerifyManifest checks that the current validated template set matches an
// approved manifest exactly.
func VerifyManifest(dir, manifestFile string) ([]string, error) {
	data, err := os.ReadFile(manifestFile)
	if err != nil {
		return nil, err
	}
	var expected Manifest
	if err := json.Unmarshal(data, &expected); err != nil {
		return nil, err
	}
	temporary := filepath.Join(filepath.Dir(manifestFile), ".neoscanner-manifest-check.json")
	actual, err := WriteManifest(dir, temporary)
	_ = os.Remove(temporary)
	if err != nil {
		return nil, err
	}
	want := map[string]string{}
	got := map[string]string{}
	for _, entry := range expected.Templates {
		want[entry.Path] = entry.SHA256
	}
	for _, entry := range actual.Templates {
		got[entry.Path] = entry.SHA256
	}
	issues := []string{}
	for path, hash := range want {
		if current, ok := got[path]; !ok {
			issues = append(issues, "missing template: "+path)
		} else if current != hash {
			issues = append(issues, "modified template: "+path)
		}
	}
	for path := range got {
		if _, ok := want[path]; !ok {
			issues = append(issues, "unexpected template: "+path)
		}
	}
	sort.Strings(issues)
	return issues, nil
}

// WriteManifest records hashes of validated templates for review and CI.
func WriteManifest(dir, output string) (Manifest, error) {
	report, err := LintDirectory(dir)
	if err != nil {
		return Manifest{}, err
	}
	if len(report.Issues) > 0 {
		return Manifest{}, fmt.Errorf("cannot manifest invalid templates")
	}
	manifest := Manifest{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Templates: []ManifestEntry{}}
	err = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") && !strings.HasSuffix(strings.ToLower(info.Name()), ".yml") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(data)
		relative, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		manifest.Templates = append(manifest.Templates, ManifestEntry{Path: filepath.ToSlash(relative), SHA256: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return Manifest{}, err
	}
	sort.Slice(manifest.Templates, func(i, j int) bool { return manifest.Templates[i].Path < manifest.Templates[j].Path })
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err = os.WriteFile(output, data, 0644); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}
