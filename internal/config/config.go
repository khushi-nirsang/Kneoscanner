package config

import (
	"fmt"
	"github.com/spf13/viper"
)

type Config struct {
	Threads     int    `mapstructure:"threads"`
	Timeout     int    `mapstructure:"timeout"`
	OutputDir   string `mapstructure:"output_dir"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("configs")

	viper.SetDefault("threads", 50)
	viper.SetDefault("timeout", 10)
	viper.SetDefault("output_dir", "reports")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Using default config")
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	fmt.Printf("📋 Config loaded: %d threads\n", cfg.Threads)
	return &cfg, nil
}
