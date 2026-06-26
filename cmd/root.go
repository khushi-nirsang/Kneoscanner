package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/khushi-nirsang/neoscanner/internal/config"
	"github.com/khushi-nirsang/neoscanner/internal/gui"
	"github.com/khushi-nirsang/neoscanner/internal/scan"
	"github.com/khushi-nirsang/neoscanner/internal/templates"
	"github.com/spf13/cobra"
)

var (
	target                    string
	targetList                string
	threads                   int
	templateDir               string
	severity                  string
	outputFile                string
	parameters                []string
	scanProfile               string
	authorizationAcknowledged bool
	guiMode                   bool
	guiAddress                string
	guiNoBrowser              bool
	harFile                   string
	baselineFile              string
	failOn                    string
	lintTemplates             bool
	templateManifest          string
	verifyTemplateManifest    string
	configFile                string
	aiEnabled                 bool
	aiProvider                string
	aiEndpoint                string
	aiModel                   string
	aiAPIKeyEnv               string
)

var rootCmd = &cobra.Command{
	Use:           "kneoscanner",
	Short:         "Fast OWASP-focused vulnerability scanner",
	SilenceUsage:  true,
	SilenceErrors: true,
	Long: `KneoScanner

A CLI and local GUI vulnerability scanner focused on OWASP Top 10 web issues,
template-driven testing, discovery, evidence capture, and professional reports.

Examples:
  kneoscanner -u https://example.com
  kneoscanner -u https://example.com --profile active --acknowledge-authorization
  kneoscanner --gui
`,
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
	if verifyTemplateManifest != "" {
		dir := effectiveTemplateDir(cmd)
		issues, err := templates.VerifyManifest(dir, verifyTemplateManifest)
		if err != nil {
			return err
		}
		if len(issues) > 0 {
			for _, issue := range issues {
				color.Red("Template integrity: %s", issue)
			}
			return fmt.Errorf("template manifest verification failed")
		}
		color.Green("Template manifest verified: %s", verifyTemplateManifest)
		return nil
	}

	if templateManifest != "" {
		dir := effectiveTemplateDir(cmd)
		manifest, err := templates.WriteManifest(dir, templateManifest)
		if err != nil {
			return err
		}
		color.Green("Template manifest saved: %s (%d templates)", templateManifest, len(manifest.Templates))
		return nil
	}

	if lintTemplates {
		dir := effectiveTemplateDir(cmd)
		report, err := templates.LintDirectory(dir)
		if err != nil {
			return err
		}
		for _, issue := range report.Issues {
			color.Red("Invalid template: %s", issue)
		}
		color.Cyan("Template lint: %d checked, %d valid, %d invalid", report.Checked, report.Valid, len(report.Issues))
		if len(report.Issues) > 0 {
			return fmt.Errorf("template lint failed")
		}
		return nil
	}

	if guiMode {
		return gui.Serve(guiAddress, !guiNoBrowser, configFile)
	}

	printBanner()

	cfg, err := config.LoadConfigFile(configFile)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	applyCLIOverrides(cmd, cfg)
	targets := getTargets(target, targetList)
	if len(targets) == 0 {
		return fmt.Errorf("no targets supplied, use -u or -l")
	}

	if cfg.ScanProfile == "active" || cfg.ScanProfile == "intrusive" {
		color.Yellow("[!] %s scan selected. Run only against targets you are authorized to test.", cfg.ScanProfile)
	}

	color.Cyan(
		"[*] Targets: %d | Threads: %d | Profile: %s | Severity: %s",
		len(targets),
		cfg.Threads,
		cfg.ScanProfile,
		cfg.Severity,
	)

	scanner, err := scan.Run(cfg, targets, parameters, authorizationAcknowledged)
	if err != nil {
		return err
	}

	color.Green("\n[OK] Scan completed | Findings: %d", len(scanner.Results.Items))
	return nil
}

func effectiveTemplateDir(cmd *cobra.Command) string {
	if cmd.Flags().Changed("templates") {
		return templateDir
	}
	return "templates"
}

func printBanner() {
	color.Cyan(`
██╗  ██╗███╗   ██╗███████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██║ ██╔╝████╗  ██║██╔════╝██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
█████╔╝ ██╔██╗ ██║█████╗  ██║   ██║███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═██╗ ██║╚██╗██║██╔══╝  ██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██╗██║ ╚████║███████╗╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

                 OWASP-focused Web Vulnerability Scanner | CLI + Local GUI
`)
}

func applyCLIOverrides(cmd *cobra.Command, cfg *config.Config) {
	if cmd.Flags().Changed("threads") {
		cfg.Threads = threads
	}
	if cmd.Flags().Changed("templates") {
		cfg.Templates = templateDir
	}
	if cmd.Flags().Changed("severity") {
		cfg.Severity = severity
	}
	if cmd.Flags().Changed("output") {
		cfg.Output = outputFile
	}
	if cmd.Flags().Changed("profile") {
		cfg.ScanProfile = scanProfile
	}
	if cmd.Flags().Changed("har") {
		cfg.HARFile = harFile
	}
	if cmd.Flags().Changed("baseline") {
		cfg.BaselineFile = baselineFile
	}
	if cmd.Flags().Changed("fail-on") {
		cfg.FailOn = failOn
	}
	if cmd.Flags().Changed("ai") {
		cfg.AIEnabled = aiEnabled
	}
	if cmd.Flags().Changed("ai-provider") {
		cfg.AIProvider = aiProvider
	}
	if cmd.Flags().Changed("ai-endpoint") {
		cfg.AIEndpoint = aiEndpoint
	}
	if cmd.Flags().Changed("ai-model") {
		cfg.AIModel = aiModel
	}
	if cmd.Flags().Changed("ai-api-key-env") {
		cfg.AIAPIKeyEnv = aiAPIKeyEnv
	}

	if cfg.Threads <= 0 {
		cfg.Threads = 25
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10
	}
	if cfg.Templates == "" {
		cfg.Templates = "templates"
	}
	if cfg.Output == "" {
		cfg.Output = "reports/results.json"
	}
}

func getTargets(single, listFile string) []string {
	targets := []string{}
	if single != "" {
		targets = append(targets, single)
	}

	if listFile != "" {
		file, err := os.Open(listFile)
		if err != nil {
			fmt.Printf("Failed to open target list: %s\n", listFile)
			return targets
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, line)
		}
	}

	return removeDuplicates(targets)
}

func removeDuplicates(targets []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		result = append(result, target)
	}
	return result
}

func init() {
	rootCmd.Flags().StringVarP(&target, "target", "u", "", "Single target URL")
	rootCmd.Flags().StringVar(&scanProfile, "profile", "safe", "Scan profile: passive, safe, active, intrusive")
	rootCmd.Flags().BoolVar(&authorizationAcknowledged, "acknowledge-authorization", false, "Confirm you are authorized to run active or intrusive tests")
	rootCmd.Flags().StringSliceVarP(&parameters, "parameter", "p", nil, "Only select discovered parameter names for active testing (comma-separated)")
	rootCmd.Flags().StringVarP(&targetList, "list", "l", "", "Target list file")
	rootCmd.Flags().IntVarP(&threads, "threads", "c", 25, "Number of concurrent threads")
	rootCmd.Flags().StringVarP(&templateDir, "templates", "t", "templates", "Templates directory")
	rootCmd.Flags().StringVarP(&severity, "severity", "s", "", "Minimum severity (info,low,medium,high,critical)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output JSON report")
	rootCmd.Flags().BoolVar(&guiMode, "gui", false, "Start the local browser-based GUI")
	rootCmd.Flags().StringVar(&guiAddress, "gui-address", "127.0.0.1:8080", "Loopback address for the GUI")
	rootCmd.Flags().BoolVar(&guiNoBrowser, "gui-no-browser", false, "Do not automatically open the GUI in a browser")
	rootCmd.Flags().StringVar(&harFile, "har", "", "Import same-origin endpoints from a HAR file")
	rootCmd.Flags().StringVar(&baselineFile, "baseline", "", "Compare findings with a previous JSON report")
	rootCmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with failure when a finding is at or above this severity")
	rootCmd.Flags().BoolVar(&lintTemplates, "lint-templates", false, "Validate templates and payload references without scanning")
	rootCmd.Flags().StringVar(&templateManifest, "template-manifest", "", "Write a SHA-256 manifest of validated templates to this file")
	rootCmd.Flags().StringVar(&verifyTemplateManifest, "verify-template-manifest", "", "Verify templates against an approved SHA-256 manifest")
	rootCmd.Flags().StringVar(&configFile, "config", "", "Explicit configuration file path")
	rootCmd.Flags().BoolVar(&aiEnabled, "ai", false, "Generate AI analyst summary in reports")
	rootCmd.Flags().StringVar(&aiProvider, "ai-provider", "local", "AI provider: local or openai")
	rootCmd.Flags().StringVar(&aiEndpoint, "ai-endpoint", "https://api.openai.com/v1/chat/completions", "OpenAI-compatible chat completions endpoint")
	rootCmd.Flags().StringVar(&aiModel, "ai-model", "gpt-4o-mini", "AI model name")
	rootCmd.Flags().StringVar(&aiAPIKeyEnv, "ai-api-key-env", "OPENAI_API_KEY", "Environment variable containing the AI API key")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}
