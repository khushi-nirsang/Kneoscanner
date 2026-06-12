package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

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
)

var rootCmd = &cobra.Command{
	Use:   "neoscanner",
	Short: "NeoScanner - Next Generation Vulnerability Scanner",
	Long:  `A fast, extensible, template-based vulnerability scanner`,
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("NeoScanner starting...")

		cfg, err := config.LoadConfig()
		if err != nil {
			color.Red("Config error: %v", err)
			os.Exit(1)
		}

		if threads > 0 {
			cfg.Threads = threads
		}

		scanner := engine.NewScanner(cfg.Threads, cfg.Timeout)

		if templateDir == "" {
			templateDir = "templates"
		}
		scanner.LoadTemplates(templateDir)

		targets := getTargets(target, targetList)
		if len(targets) == 0 {
			color.Red("Error: Use -u <url> or -l <targets.txt>")
			os.Exit(1)
		}

		color.Cyan("[*] Starting scan on %d target(s) | Threads: %d | Severity: %s", len(targets), cfg.Threads, severity)

		var wg sync.WaitGroup
		sem := make(chan struct{}, cfg.Threads)

		for _, t := range targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(url string) {
				defer wg.Done()
				defer func() { <-sem }()

				color.Cyan("[→] Scanning: %s", url)
				scanner.StartScan(url)
			}(t)
		}

		wg.Wait()

		scanner.SaveResults("reports/results.json")
		color.Green("\n✅ Scan completed. Total Findings: %d", len(scanner.Results.Items))
	},
}

func getTargets(single, listFile string) []string {
	var targets []string

	if single != "" {
		targets = append(targets, single)
	}

	if listFile != "" {
		file, err := os.Open(listFile)
		if err != nil {
			fmt.Printf("⚠️ Could not open target list: %s\n", listFile)
			return targets
		}
		defer file.Close()

		fileScanner := bufio.NewScanner(file)
		for fileScanner.Scan() {
			line := strings.TrimSpace(fileScanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	return targets
}

func init() {
	rootCmd.Flags().StringVarP(&target, "target", "u", "", "Single target URL")
	rootCmd.Flags().StringVarP(&targetList, "list", "l", "", "Target list file")
	rootCmd.Flags().IntVarP(&threads, "threads", "c", 50, "Number of concurrent threads")
	rootCmd.Flags().StringVarP(&templateDir, "templates", "t", "templates", "Templates directory")
	rootCmd.Flags().StringVarP(&severity, "severity", "s", "", "Severity filter (info,low,medium,high,critical)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}