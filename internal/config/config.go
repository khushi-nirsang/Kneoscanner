package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Target string `mapstructure:"target"`

	Threads int `mapstructure:"threads"`
	Timeout int `mapstructure:"timeout"`

	Output       string `mapstructure:"output"`
	OutputDir    string `mapstructure:"output_dir"`
	HistoryFile  string `mapstructure:"history_file"`
	BaselineFile string `mapstructure:"baseline_file"`

	Templates string `mapstructure:"templates"`
	Severity  string `mapstructure:"severity"`
	FailOn    string `mapstructure:"fail_on"`

	UserAgent   string            `mapstructure:"user_agent"`
	AuthHeaders map[string]string `mapstructure:"auth_headers"`

	FollowRedirects bool `mapstructure:"follow_redirects"`
	MaxRedirects    int  `mapstructure:"max_redirects"`
	VerifySSL       bool `mapstructure:"verify_ssl"`

	Retries                int    `mapstructure:"retries"`
	RetryDelay             int    `mapstructure:"retry_delay"`
	MaxResponseBytes       int64  `mapstructure:"max_response_bytes"`
	AllowExternalURLs      bool   `mapstructure:"allow_external_urls"`
	Crawl                  bool   `mapstructure:"crawl"`
	CrawlMaxDepth          int    `mapstructure:"crawl_max_depth"`
	CrawlMaxPages          int    `mapstructure:"crawl_max_pages"`
	DiscoverScripts        bool   `mapstructure:"discover_scripts"`
	DiscoverOpenAPI        bool   `mapstructure:"discover_openapi"`
	DiscoverSitemap        bool   `mapstructure:"discover_sitemap"`
	HARFile                string `mapstructure:"har_file"`
	ActiveParameterTesting bool   `mapstructure:"active_parameter_testing"`
	MaxParameterMutations  int    `mapstructure:"max_parameter_mutations"`
	PayloadsPerParameter   int    `mapstructure:"payloads_per_parameter"`
	ActivePostFormTesting  bool   `mapstructure:"active_post_form_testing"`
	MaxPostFormMutations   int    `mapstructure:"max_post_form_mutations"`
	ScanProfile            string `mapstructure:"scan_profile"`
	RequestDelay           int    `mapstructure:"request_delay"`
	EvidenceMaxBytes       int64  `mapstructure:"evidence_max_bytes"`
	RedactSensitiveData    bool   `mapstructure:"redact_sensitive_data"`

	HTMLReport  bool `mapstructure:"html_report"`
	JSONReport  bool `mapstructure:"json_report"`
	PDFReport   bool `mapstructure:"pdf_report"`
	SARIFReport bool `mapstructure:"sarif_report"`

	ShowProgress bool `mapstructure:"show_progress"`
	ShowBanner   bool `mapstructure:"show_banner"`

	Fingerprinting bool `mapstructure:"fingerprinting"`
	ColorOutput    bool `mapstructure:"color_output"`
	OWASPMode      bool `mapstructure:"owasp_mode"`

	AIEnabled   bool   `mapstructure:"ai_enabled"`
	AIProvider  string `mapstructure:"ai_provider"`
	AIEndpoint  string `mapstructure:"ai_endpoint"`
	AIModel     string `mapstructure:"ai_model"`
	AIAPIKeyEnv string `mapstructure:"ai_api_key_env"`
}

func LoadConfig() (*Config, error) {
	return LoadConfigFile("")
}

func LoadConfigFile(configFile string) (*Config, error) {
	viper.Reset()

	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./configs")
	}

	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		if configFile != "" {
			return nil, fmt.Errorf("read config %q: %w", configFile, err)
		}
		fmt.Println("Using built-in default configuration")
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	fmt.Printf("Config loaded: %d threads, %d sec timeout\n", cfg.Threads, cfg.Timeout)
	return &cfg, nil
}

func setDefaults() {
	viper.SetDefault("threads", 50)
	viper.SetDefault("timeout", 10)
	viper.SetDefault("output", "reports/results.json")
	viper.SetDefault("output_dir", "reports")
	viper.SetDefault("history_file", "reports/history.json")
	viper.SetDefault("templates", "templates")
	viper.SetDefault("severity", "info")
	viper.SetDefault("fail_on", "")
	viper.SetDefault("user_agent", "KneoScanner/1.0")
	viper.SetDefault("follow_redirects", true)
	viper.SetDefault("max_redirects", 5)
	viper.SetDefault("verify_ssl", true)
	viper.SetDefault("retries", 2)
	viper.SetDefault("retry_delay", 500)
	viper.SetDefault("max_response_bytes", 2*1024*1024)
	viper.SetDefault("allow_external_urls", false)
	viper.SetDefault("crawl", true)
	viper.SetDefault("crawl_max_depth", 3)
	viper.SetDefault("crawl_max_pages", 100)
	viper.SetDefault("discover_scripts", true)
	viper.SetDefault("discover_openapi", true)
	viper.SetDefault("discover_sitemap", true)
	viper.SetDefault("active_parameter_testing", true)
	viper.SetDefault("max_parameter_mutations", 200)
	viper.SetDefault("payloads_per_parameter", 5)
	viper.SetDefault("active_post_form_testing", true)
	viper.SetDefault("max_post_form_mutations", 50)
	viper.SetDefault("scan_profile", "safe")
	viper.SetDefault("request_delay", 100)
	viper.SetDefault("evidence_max_bytes", 65536)
	viper.SetDefault("redact_sensitive_data", true)
	viper.SetDefault("html_report", true)
	viper.SetDefault("json_report", true)
	viper.SetDefault("pdf_report", true)
	viper.SetDefault("sarif_report", true)
	viper.SetDefault("show_progress", true)
	viper.SetDefault("show_banner", true)
	viper.SetDefault("fingerprinting", true)
	viper.SetDefault("color_output", true)
	viper.SetDefault("owasp_mode", true)
	viper.SetDefault("ai_enabled", false)
	viper.SetDefault("ai_provider", "local")
	viper.SetDefault("ai_endpoint", "https://api.openai.com/v1/chat/completions")
	viper.SetDefault("ai_model", "gpt-4o-mini")
	viper.SetDefault("ai_api_key_env", "OPENAI_API_KEY")
}
