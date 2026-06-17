package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/khushi-nirsang/neoscanner/internal/config"
	"github.com/khushi-nirsang/neoscanner/internal/engine"
	"github.com/spf13/cobra"
)

var (
	target      string
	targetList  string
	threads     int
	templateDir string
	severity    string
	outputFile  string
)

var rootCmd = &cobra.Command{
	Use:   "neoscanner",
	Short: "Fast OWASP-focused vulnerability scanner",
	Long: `NeoScanner

A fast, accurate and extensible vulnerability scanner
focused on OWASP Top 10 vulnerabilities with low false positives.
`,
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {

	color.Cyan("NeoScanner v1.0")

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	applyCLIOverrides(cmd, cfg)

	targets := getTargets(target, targetList)

	if len(targets) == 0 {
		return fmt.Errorf("no targets supplied, use -u or -l")
	}

	scanner := engine.NewScanner(
		cfg.Threads,
		cfg.Timeout,
	)

	color.Cyan(
		"[*] Targets: %d | Threads: %d | Severity: %s",
		len(targets),
		cfg.Threads,
		cfg.Severity,
	)

	if err := scanner.LoadTemplates(cfg.Templates); err != nil {
		return err
	}

	for _, t := range targets {
		scanner.StartScan(strings.TrimSpace(t))
	}

	scanner.Results.FilterBySeverity(cfg.Severity)

	scanner.SaveResults(cfg.Output)

	color.Green(
		"\n✔ Scan completed | Findings: %d",
		len(scanner.Results.Items),
	)

	return nil
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

	var targets []string

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

			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "#") {
				continue
			}

			targets = append(targets, line)
		}
	}

	return removeDuplicates(targets)
}

func removeDuplicates(targets []string) []string {

	seen := make(map[string]struct{})
	result := make([]string, 0)

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

	rootCmd.Flags().StringVarP(
		&target,
		"target",
		"u",
		"",
		"Single target URL",
	)

	rootCmd.Flags().StringVarP(
		&targetList,
		"list",
		"l",
		"",
		"Target list file",
	)

	rootCmd.Flags().IntVarP(
		&threads,
		"threads",
		"c",
		25,
		"Number of concurrent threads",
	)

	rootCmd.Flags().StringVarP(
		&templateDir,
		"templates",
		"t",
		"templates",
		"Templates directory",
	)

	rootCmd.Flags().StringVarP(
		&severity,
		"severity",
		"s",
		"",
		"Minimum severity (info,low,medium,high,critical)",
	)

	rootCmd.Flags().StringVarP(
		&outputFile,
		"output",
		"o",
		"",
		"Output JSON report",
	)
}

func Execute() {

	if err := rootCmd.Execute(); err != nil {
		color.Red("Error: %v", err)
		os.Exit(1)
	}
}