package templates

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Template struct {
	ID       string      `yaml:"id"`
	Info     Info        `yaml:"info"`
	Requests []Request   `yaml:"requests"`
	Tags     StringSlice `yaml:"tags,omitempty"`
}

type Info struct {
	Name        string      `yaml:"name"`
	Author      string      `yaml:"author"`
	Severity    string      `yaml:"severity"`
	Description string      `yaml:"description,omitempty"`

	Tags       StringSlice `yaml:"tags,omitempty"`
	References StringSlice `yaml:"references,omitempty"`
}

type Request struct {
	Method string `yaml:"method"`

	Path []string `yaml:"path"`

	Headers Headers `yaml:"headers,omitempty"`

	Body string `yaml:"body,omitempty"`

	Timeout int `yaml:"timeout,omitempty"`

	Redirects bool `yaml:"redirects,omitempty"`

	Matchers []Matcher `yaml:"matchers"`

	MatchersCondition string `yaml:"matchers-condition,omitempty"`

	Extractors []Extractor `yaml:"extractors,omitempty"`
}

type Matcher struct {
	Type string `yaml:"type"`

	Part string `yaml:"part,omitempty"`

	Words []string `yaml:"words,omitempty"`

	Status []int `yaml:"status,omitempty"`

	Regex []string `yaml:"regex,omitempty"`

	Negative bool `yaml:"negative,omitempty"`

	Condition string `yaml:"condition,omitempty"`
}

type Extractor struct {
	Type string `yaml:"type"`

	Part string `yaml:"part,omitempty"`

	Regex []string `yaml:"regex,omitempty"`
}

type Headers map[string]string

type StringSlice []string

func (s *StringSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {

	case yaml.SequenceNode:
		items := make([]string, 0, len(value.Content))

		for _, item := range value.Content {
			items = append(items, strings.TrimSpace(item.Value))
		}

		*s = items

	case yaml.ScalarNode:

		if strings.TrimSpace(value.Value) == "" {
			*s = nil
			return nil
		}

		*s = []string{
			strings.TrimSpace(value.Value),
		}

	default:
		return fmt.Errorf("invalid string list format")
	}

	return nil
}

func (h *Headers) UnmarshalYAML(value *yaml.Node) error {

	headers := Headers{}

	switch value.Kind {

	case yaml.MappingNode:

		for i := 0; i < len(value.Content); i += 2 {
			key := strings.TrimSpace(value.Content[i].Value)
			val := strings.TrimSpace(value.Content[i+1].Value)

			headers[key] = val
		}

	case yaml.SequenceNode:

		for _, item := range value.Content {

			parts := strings.SplitN(item.Value, ":", 2)

			if len(parts) != 2 {
				return fmt.Errorf(
					"invalid header %q, expected Key: Value",
					item.Value,
				)
			}

			headers[strings.TrimSpace(parts[0])] =
				strings.TrimSpace(parts[1])
		}

	case yaml.ScalarNode:

		if strings.TrimSpace(value.Value) == "" {
			*h = headers
			return nil
		}

		return fmt.Errorf(
			"invalid headers value %q",
			value.Value,
		)

	default:
		return fmt.Errorf("invalid headers format")
	}

	*h = headers

	return nil
}

func LoadTemplate(filePath string) (*Template, error) {

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var tmpl Template

	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}

	return &tmpl, nil
}