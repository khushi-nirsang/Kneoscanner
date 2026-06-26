package history

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/khushi-nirsang/neoscanner/internal/engine"
)

type Record struct {
	ScanID     string         `json:"scan_id"`
	Targets    []string       `json:"targets"`
	Profile    string         `json:"profile"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	DurationMS int64          `json:"duration_ms"`
	Findings   int            `json:"findings"`
	Severity   map[string]int `json:"severity"`
	Report     string         `json:"report"`
}

// Load returns scan history newest-first. A missing file is treated as an
// empty history so the GUI can render a clean first-run state.
func Load(path string) ([]Record, error) {
	if strings.TrimSpace(path) == "" {
		return []Record{}, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []Record{}, nil
	}
	if err != nil {
		return nil, err
	}
	records := []Record{}
	if len(strings.TrimSpace(string(data))) == 0 {
		return records, nil
	}
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return Sorted(records), nil
}

// Append records a compact, secret-free scan summary. It keeps the newest 100
// records so local history remains useful without becoming an unbounded store.
func Append(path string, targets []string, profile, report string, started, finished time.Time, items []engine.ScanResult) error {
	records := []Record{}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &records)
	}
	canonical := strings.Join(targets, "|") + "|" + profile + "|" + started.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(canonical))
	severity := map[string]int{}
	for _, item := range items {
		severity[strings.ToLower(item.Severity)]++
	}
	record := Record{ScanID: "scan-" + fmtHash(sum[:8]), Targets: append([]string(nil), targets...), Profile: profile, StartedAt: started, FinishedAt: finished, DurationMS: finished.Sub(started).Milliseconds(), Findings: len(items), Severity: severity, Report: report}
	records = append([]Record{record}, records...)
	if len(records) > 100 {
		records = records[:100]
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
func fmtHash(data []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&15]
	}
	return string(out)
}
func Sorted(records []Record) []Record {
	copyRecords := append([]Record(nil), records...)
	sort.Slice(copyRecords, func(i, j int) bool { return copyRecords[i].StartedAt.After(copyRecords[j].StartedAt) })
	return copyRecords
}
