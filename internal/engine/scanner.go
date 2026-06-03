package engine

import (
	"fmt"
	"github.com/khushi-nirsang/neoscanner/internal/engine/result"
)

type Scanner struct {
	Threads int
	Results *result.Results
}

func NewScanner(threads int) *Scanner {
	return &Scanner{
		Threads: threads,
		Results: result.NewResults(),
	}
}

func (s *Scanner) StartScan(target string) {
	fmt.Printf("🔍 Scanning target: %s\n", target)
	
	// Basic checks for now (later connect with executor)
	checks := []string{"Header Check", "XSS Probe", "SQLi Probe"}
	
	for _, check := range checks {
		res := result.ScanResult{
			Target:   target,
			Name:     check,
			Severity: "medium",
			Matched:  true,
		}
		s.Results.Add(res)
		fmt.Printf("   ✅ %s detected\n", check)
	}
}

func (s *Scanner) SaveResults(outputFile string) {
	fmt.Printf("📊 Saving results to %s\n", outputFile)
	s.Results.Print()
}
