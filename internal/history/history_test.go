package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/khushi-nirsang/neoscanner/internal/engine"
)

func TestAppendWritesSecretFreeScanSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	start := time.Now().Add(-time.Second)
	if err := Append(path, []string{"https://app.test"}, "safe", "reports/results.json", start, time.Now(), []engine.ScanResult{{Severity: "high", Payload: "should-not-be-stored"}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || string(data) == "should-not-be-stored" {
		t.Fatalf("history leaked finding data: %s", data)
	}
	var records []Record
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Findings != 1 || records[0].Severity["high"] != 1 || records[0].ScanID == "" {
		t.Fatalf("unexpected history: %#v", records)
	}
}

func TestLoadReturnsNewestFirstAndAllowsMissingHistory(t *testing.T) {
	missing, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("expected empty missing history, got %#v", missing)
	}

	path := filepath.Join(t.TempDir(), "history.json")
	old := Record{ScanID: "old", StartedAt: time.Now().Add(-time.Hour)}
	newer := Record{ScanID: "new", StartedAt: time.Now()}
	data, err := json.Marshal([]Record{old, newer})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	records, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].ScanID != "new" || records[1].ScanID != "old" {
		t.Fatalf("history was not sorted newest-first: %#v", records)
	}
}
