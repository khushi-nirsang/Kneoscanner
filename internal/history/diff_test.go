package history

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/engine"
)

func TestCompareReportSeparatesNewFixedAndUnchanged(t *testing.T) {
	path:=filepath.Join(t.TempDir(),"baseline.json")
	baseline:=`{"items":[{"fingerprint":"keep"},{"fingerprint":"fixed"}]}`
	if err:=os.WriteFile(path,[]byte(baseline),0644);err!=nil{t.Fatal(err)}
	diff,err:=CompareReport(path,[]engine.ScanResult{{Fingerprint:"keep"},{Fingerprint:"new"}});if err!=nil{t.Fatal(err)}
	if len(diff.New)!=1||diff.New[0]!="new"||len(diff.Unchanged)!=1||diff.Unchanged[0]!="keep"||len(diff.Fixed)!=1||diff.Fixed[0]!="fixed" { t.Fatalf("unexpected diff: %#v",diff) }
}
