package templates

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Template struct {
	ID          string    `yaml:"id"`
	Info        Info      `yaml:"info"`
	Requests    []Request `yaml:"requests"`
	Tags        []string  `yaml:"tags"`
}

type Info struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

type Request struct {
	Method   string            `yaml:"method"`
	Path     []string          `yaml:"path"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Body     string            `yaml:"body,omitempty"`
	Matchers []Matcher         `yaml:"matchers"`
}

type Matcher struct {
	Type       string   `yaml:"type"` // word, status, regex
	Part       string   `yaml:"part"` // body, header
	Words      []string `yaml:"words,omitempty"`
	Status     []int    `yaml:"status,omitempty"`
	Regex      string   `yaml:"regex,omitempty"`
	Negative   bool     `yaml:"negative,omitempty"`
	Condition  string   `yaml:"condition"` // and, or
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

	fmt.Printf("📋 Loaded: %s [%s]\n", t.Info.Name, t.Info.Severity)
	return &t, nil
}