package templates

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"gopkg.in/yaml.v3"
)

type Template struct {
	ID          string `yaml:"id"`
	Info        struct {
		Name        string `yaml:"name"`
		Severity    string `yaml:"severity"`
		Description string `yaml:"description"`
	} `yaml:"info"`
	Requests []Request `yaml:"requests"`
}

type Request struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

func LoadTemplates(dir string) ([]Template, error) {
	var templates []Template
	files, err := filepath.Glob(filepath.Join(dir, "**/*.yaml"))
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("Warning: Could not read %s\n", file)
			continue
		}

		var t Template
		if err := yaml.Unmarshal(data, &t); err != nil {
			fmt.Printf("Warning: Invalid YAML in %s\n", file)
			continue
		}
		templates = append(templates, t)
	}

	return templates, nil
}
