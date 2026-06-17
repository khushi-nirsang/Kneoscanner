package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Target string `mapstructure:"target"`

	Threads int `mapstructure:"threads"`
	Timeout int `mapstructure:"timeout"`

	Output    string `mapstructure:"output"`
	OutputDir string `mapstructure:"output_dir"`

	Templates string `mapstructure:"templates"`
	Severity  string `mapstructure:"severity"`

	UserAgent string `mapstructure:"user_agent"`

	FollowRedirects bool `mapstructure:"follow_redirects"`
	MaxRedirects    int  `mapstructure:"max_redirects"`

	VerifySSL bool `mapstructure:"verify_ssl"`

	Retries   int `mapstructure:"retries"`
	RetryDelay int `mapstructure:"retry_delay"`

	HTMLReport bool `mapstructure:"html_report"`
	JSONReport bool `mapstructure:"json_report"`

	ShowProgress bool `mapstructure:"show_progress"`
	ShowBanner   bool `mapstructure:"show_banner"`

	Fingerprinting bool `mapstructure:"fingerprinting"`
	ColorOutput    bool `mapstructure:"color_output"`

	OWASPMode bool `mapstructure:"owasp_mode"`
}

func LoadConfig() (*Config, error) {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	viper.AddConfigPath(".")
	viper.AddConfigPath("./configs")

	// Defaults

	viper.SetDefault("threads", 50)
	viper.SetDefault("timeout", 10)

	viper.SetDefault("output", "reports/results.json")
	viper.SetDefault("output_dir", "reports")

	viper.SetDefault("templates", "templates")

	viper.SetDefault("severity", "info")

	viper.SetDefault("user_agent", "NeoScanner/1.0")

	viper.SetDefault("follow_redirects", true)
	viper.SetDefault("max_redirects", 5)

	viper.SetDefault("verify_ssl", true)

	viper.SetDefault("retries", 2)
	viper.SetDefault("retry_delay", 500)

	viper.SetDefault("html_report", true)
	viper.SetDefault("json_report", true)

	viper.SetDefault("show_progress", true)
	viper.SetDefault("show_banner", true)

	viper.SetDefault("fingerprinting", true)
	viper.SetDefault("color_output", true)

	viper.SetDefault("owasp_mode", true)

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Using default configuration")
	}

	var cfg Config

	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	fmt.Printf(
		"📋 Config loaded: %d threads, %d sec timeout\n",
		cfg.Threads,
		cfg.Timeout,
	)

	return &cfg, nil
}