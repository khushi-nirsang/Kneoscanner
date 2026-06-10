package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/khushi-nirsang/neoscanner/internal/templates"
	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

type Scanner struct {
	Threads    int
	Results    *Results
	httpClient *utils.HTTPClient
	templates  []*templates.Template
	mu         sync.Mutex
}

func NewScanner(threads int, timeout int) *Scanner {
	return &Scanner{
		Threads:    threads,
		Results:    NewResults(),
		httpClient: utils.NewHTTPClient(timeout),
		templates:  make([]*templates.Template, 0),
	}
}

func (s *Scanner) LoadTemplates(templateDir string) {
	os.MkdirAll(templateDir, 0755)
	count := 0

	_ = filepath.Walk(templateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			fmt.Printf("📄 Trying to load: %s\n", path)
			tmpl, err := templates.LoadTemplate(path)
			if err == nil {
				s.templates = append(s.templates, tmpl)
				count++
			} else {
				fmt.Printf("❌ Failed to load %s: %v\n", name, err)
			}
		}
		return nil
	})

	fmt.Printf("🔧 Loaded %d templates\n", count)
}

func (s *Scanner) StartScan(target string) {
	fmt.Printf("🔍 Scanning target: %s\n", target)
	os.MkdirAll("reports", 0755)

	resp, err := s.httpClient.Get(target)
	if err != nil {
		fmt.Printf("❌ Failed to connect: %v\n", err)
		return
	}

	for _, tmpl := range s.templates {
		s.executeTemplate(tmpl, target, resp)
	}
}

func (s *Scanner) executeTemplate(tmpl *templates.Template, target string, resp *utils.Response) {
	for _, req := range tmpl.Requests {
		for _, matcher := range req.Matchers {
			if s.matchResponse(resp, matcher) {
				if isNoisyTemplate(tmpl.Info.Name) {
					return
				}

				s.mu.Lock()
				s.Results.Add(ScanResult{
					Target:      target,
					Name:        tmpl.Info.Name,
					Severity:    tmpl.Info.Severity,
					Matched:     true,
					Description: tmpl.Info.Description,
				})
				s.mu.Unlock()

				fmt.Printf("✅ [+] %s [%s] → %s\n", tmpl.Info.Name, tmpl.Info.Severity, target)
				return
			}
		}
	}
}

func isNoisyTemplate(name string) bool {
	noisy := []string{
		"GraphQL", "Health Check", "Admin Panel", "XML Injection", 
		"Login Page Detected", "Idempotent Method Bypass",
	}
	for _, n := range noisy {
		if strings.Contains(name, n) {
			return true
		}
	}
	return false
}

func (s *Scanner) matchResponse(resp *utils.Response, matcher templates.Matcher) bool {
	if matcher.Type == "word" {
		text := ""
		if matcher.Part == "header" {
			text = resp.Header.Get("Server")
			if text == "" {
				text = resp.Header.Get("X-Powered-By")
			}
		} else if matcher.Part == "body" {
			text = resp.BodyContent
		}

		for _, word := range matcher.Words {
			if strings.Contains(strings.ToLower(text), strings.ToLower(word)) {
				return true
			}
		}
	}
	return false
}

// Updated to accept severity filter
func (s *Scanner) SaveResults(outputFile, severityFilter string) {
	fmt.Printf("📊 Saving results to %s\n", outputFile)
	s.Results.Print()
}
