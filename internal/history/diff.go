package history

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/khushi-nirsang/neoscanner/internal/engine"
)

type Diff struct { Baseline string `json:"baseline"`; New []string `json:"new"`; Unchanged []string `json:"unchanged"`; Fixed []string `json:"fixed"` }

// CompareReport compares stable finding fingerprints with a previous JSON
// report. It never compares payload values or raw HTTP evidence.
func CompareReport(baseline string, current []engine.ScanResult) (Diff,error) {
	data,err:=os.ReadFile(baseline);if err!=nil{return Diff{},fmt.Errorf("read baseline report: %w",err)}
	var previous struct { Items []engine.ScanResult `json:"items"` };if err:=json.Unmarshal(data,&previous);err!=nil{return Diff{},fmt.Errorf("parse baseline report: %w",err)}
	old:=map[string]struct{}{};for _, item:=range previous.Items { if item.Fingerprint!="" {old[item.Fingerprint]=struct{}{}} }
	now:=map[string]struct{}{};for _, item:=range current { if item.Fingerprint!="" {now[item.Fingerprint]=struct{}{}} }
	diff:=Diff{Baseline:baseline};for fingerprint:=range now { if _,exists:=old[fingerprint];exists{diff.Unchanged=append(diff.Unchanged,fingerprint)}else{diff.New=append(diff.New,fingerprint)} };for fingerprint:=range old {if _,exists:=now[fingerprint];!exists{diff.Fixed=append(diff.Fixed,fingerprint)}};sort.Strings(diff.New);sort.Strings(diff.Unchanged);sort.Strings(diff.Fixed);return diff,nil
}
func SaveDiff(path string,diff Diff) error { data,err:=json.MarshalIndent(diff,"","  ");if err!=nil{return err};return os.WriteFile(path,data,0644) }
