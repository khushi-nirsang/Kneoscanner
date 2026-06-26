// Package scan contains the application-level scan workflow shared by the CLI
// and the local GUI. Keeping this outside cmd prevents the two interfaces from
// drifting into different scanner behavior.
package scan

import (
	"context"
	"fmt"
	"github.com/khushi-nirsang/neoscanner/internal/ai"
	"github.com/khushi-nirsang/neoscanner/internal/discovery"
	"github.com/khushi-nirsang/neoscanner/internal/history"
	"path/filepath"
	"strings"
	"time"

	"github.com/khushi-nirsang/neoscanner/internal/config"
	"github.com/khushi-nirsang/neoscanner/internal/engine"
	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

// ThresholdExceededError lets CI fail after all artifacts have been written.
type ThresholdExceededError struct {
	Severity string
	Count    int
}

func (e *ThresholdExceededError) Error() string {
	return fmt.Sprintf("scan policy failed: %d finding(s) at or above %s", e.Count, e.Severity)
}

// Run performs one scan and writes the reports selected in cfg.
func Run(cfg *config.Config, targets, parameters []string, authorizationAcknowledged bool) (*engine.Scanner, error) {
	return RunWithRuntime(context.Background(), cfg, targets, parameters, authorizationAcknowledged, nil)
}

// RunWithRuntime exposes cancellation and structured scan events to an owner
// such as the GUI without changing the scanner's result semantics.
func RunWithRuntime(ctx context.Context, cfg *config.Config, targets, parameters []string, authorizationAcknowledged bool, sink func(engine.ScanEvent)) (*engine.Scanner, error) {
	started := time.Now()
	if cfg == nil {
		return nil, fmt.Errorf("scan configuration is required")
	}
	cfg.ScanProfile = strings.ToLower(strings.TrimSpace(cfg.ScanProfile))
	if cfg.ScanProfile != "passive" && cfg.ScanProfile != "safe" && cfg.ScanProfile != "active" && cfg.ScanProfile != "intrusive" {
		return nil, fmt.Errorf("invalid scan profile %q; use passive, safe, active, or intrusive", cfg.ScanProfile)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets supplied")
	}
	if (cfg.ScanProfile == "active" || cfg.ScanProfile == "intrusive") && !authorizationAcknowledged {
		return nil, fmt.Errorf("%s scans require authorization acknowledgement", cfg.ScanProfile)
	}

	scanner := engine.NewScannerWithOptions(cfg.Threads, utils.HTTPOptions{
		Timeout:          time.Duration(cfg.Timeout) * time.Second,
		UserAgent:        cfg.UserAgent,
		DefaultHeaders:   cfg.AuthHeaders,
		FollowRedirects:  cfg.FollowRedirects,
		MaxRedirects:     cfg.MaxRedirects,
		VerifyTLS:        cfg.VerifySSL,
		Retries:          cfg.Retries,
		RetryDelay:       time.Duration(cfg.RetryDelay) * time.Millisecond,
		RequestDelay:     time.Duration(cfg.RequestDelay) * time.Millisecond,
		MaxResponseBytes: cfg.MaxResponseBytes,
	}, cfg.AllowExternalURLs)
	scanner.ConfigureRuntime(ctx, sink)
	scanner.ConfigureScanProfile(cfg.ScanProfile)
	if cfg.Crawl {
		options := engine.DiscoveryOptions{MaxDepth: cfg.CrawlMaxDepth, MaxPages: cfg.CrawlMaxPages, DiscoverScripts: cfg.DiscoverScripts, DiscoverOpenAPI: cfg.DiscoverOpenAPI, DiscoverSitemap: cfg.DiscoverSitemap}
		if cfg.HARFile != "" {
			endpoints, err := discovery.ImportHAR(cfg.HARFile)
			if err != nil {
				return nil, err
			}
			options.SeedEndpoints = endpoints
		}
		scanner.ConfigureDiscovery(options)
	}
	scanner.ConfigureParameterFilter(parameters)
	scanner.ConfigureActiveParameterTesting(cfg.ActiveParameterTesting, cfg.MaxParameterMutations, cfg.PayloadsPerParameter)
	scanner.ConfigurePostFormTesting(cfg.ActivePostFormTesting, cfg.MaxPostFormMutations)
	scanner.ConfigureEvidence(cfg.EvidenceMaxBytes, cfg.RedactSensitiveData)

	if err := scanner.LoadTemplates(cfg.Templates); err != nil {
		return nil, err
	}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target != "" {
			scanner.StartScan(target)
		}
	}
	scanner.Results.FilterBySeverity(cfg.Severity)
	if cfg.AIEnabled {
		scanner.Results.SetAIAnalysis(ai.Analyze(ctx, ai.Options{
			Enabled:   cfg.AIEnabled,
			Provider:  cfg.AIProvider,
			Endpoint:  cfg.AIEndpoint,
			Model:     cfg.AIModel,
			APIKeyEnv: cfg.AIAPIKeyEnv,
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
		}, scanner.Results.Items))
	}
	if err := scanner.SaveResultsWithOptions(cfg.Output, cfg.JSONReport, cfg.HTMLReport, cfg.PDFReport); err != nil {
		return nil, err
	}
	if cfg.BaselineFile != "" {
		diff, err := history.CompareReport(cfg.BaselineFile, scanner.Results.Items)
		if err != nil {
			return nil, err
		}
		if err := history.SaveDiff(diffOutputPath(cfg.Output), diff); err != nil {
			return nil, fmt.Errorf("save scan diff: %w", err)
		}
	}
	if cfg.HistoryFile != "" {
		if err := history.Append(cfg.HistoryFile, targets, cfg.ScanProfile, cfg.Output, started, time.Now(), scanner.Results.Items); err != nil {
			return scanner, fmt.Errorf("save scan history: %w", err)
		}
	}
	if cfg.SARIFReport {
		if err := scanner.Results.SaveSARIF(sarifOutputPath(cfg.Output)); err != nil {
			return nil, fmt.Errorf("save SARIF report: %w", err)
		}
	}
	if cfg.FailOn != "" {
		level, ok := severityLevel(cfg.FailOn)
		if !ok {
			return scanner, fmt.Errorf("invalid fail_on %q; use info, low, medium, high, or critical", cfg.FailOn)
		}
		count := 0
		for _, finding := range scanner.Results.Items {
			if findingLevel, valid := severityLevel(finding.Severity); valid && findingLevel >= level {
				count++
			}
		}
		if count > 0 {
			return scanner, &ThresholdExceededError{Severity: cfg.FailOn, Count: count}
		}
	}
	return scanner, nil
}

func severityLevel(value string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "info":
		return 1, true
	case "low":
		return 2, true
	case "medium":
		return 3, true
	case "high":
		return 4, true
	case "critical":
		return 5, true
	default:
		return 0, false
	}
}

func sarifOutputPath(output string) string {
	ext := filepath.Ext(output)
	if ext == "" {
		return output + ".sarif"
	}
	return strings.TrimSuffix(output, ext) + ".sarif"
}
func diffOutputPath(output string) string {
	ext := filepath.Ext(output)
	if ext == "" {
		return output + ".diff.json"
	}
	return strings.TrimSuffix(output, ext) + ".diff.json"
}
