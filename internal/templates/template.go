package templates

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`
}

type Info struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

type Request struct {
	Method  string   `yaml:"method"`
	Path    []string `yaml:"path"`
	Matchers []Matcher `yaml:"matchers"`
}

type Matcher struct {
	Type      string   `yaml:"type"`
	Part      string   `yaml:"part"`
	Words     []string `yaml:"words"`
	Condition string   `yaml:"condition"`
}

func LoadTemplate(filePath string) (*Template, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, err
	}

	fmt.Printf("📋 Loaded template: %s (%s)\n", t.Info.Name, t.ID)
	return &t, nil
}
