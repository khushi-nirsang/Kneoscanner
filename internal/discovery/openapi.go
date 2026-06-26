package discovery

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/khushi-nirsang/neoscanner/internal/utils"
	"gopkg.in/yaml.v3"
)

// DiscoverOpenAPI probes a small, conventional list of same-origin API-spec
// locations. A missing specification is normal and never fails a crawl.
func DiscoverOpenAPI(ctx context.Context, client *utils.HTTPClient, target string) []Endpoint {
	candidates := []string{"/openapi.json", "/swagger.json", "/openapi.yaml", "/openapi.yml"}
	found := make(map[string]Endpoint)
	for _, path := range candidates {
		specURL := resolveSpecURL(target, path)
		if specURL == "" {
			continue
		}
		response, err := client.GetScopedContext(ctx, target, specURL)
		if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
			continue
		}
		for _, endpoint := range parseOpenAPI(target, response.BodyContent) {
			found[endpoint.Method+" "+endpoint.URL] = endpoint
		}
	}
	values := make([]Endpoint, 0, len(found))
	for _, endpoint := range found {
		values = append(values, endpoint)
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].URL == values[j].URL {
			return values[i].Method < values[j].Method
		}
		return values[i].URL < values[j].URL
	})
	return values
}

type openAPIDocument struct {
	OpenAPI string                                 `yaml:"openapi"`
	Swagger string                                 `yaml:"swagger"`
	Paths   map[string]map[string]openAPIOperation `yaml:"paths"`
}
type openAPIOperation struct {
	Parameters []openAPIParameter `yaml:"parameters"`
}
type openAPIParameter struct {
	Name string `yaml:"name"`
	In   string `yaml:"in"`
}

func parseOpenAPI(target, raw string) []Endpoint {
	var document openAPIDocument
	if yaml.Unmarshal([]byte(raw), &document) != nil || (document.OpenAPI == "" && document.Swagger == "") {
		return nil
	}
	validMethods := map[string]bool{http.MethodGet: true, http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true, http.MethodHead: true, http.MethodOptions: true}
	endpoints := make([]Endpoint, 0)
	for path, operations := range document.Paths {
		for method, operation := range operations {
			method = strings.ToUpper(strings.TrimSpace(method))
			if !validMethods[method] {
				continue
			}
			resolved := resolveSpecURL(target, path)
			if resolved == "" {
				continue
			}
			parameters := make([]string, 0)
			for _, parameter := range operation.Parameters {
				if strings.EqualFold(parameter.In, "query") && strings.TrimSpace(parameter.Name) != "" {
					parameters = append(parameters, parameter.Name)
				}
			}
			sort.Strings(parameters)
			endpoints = append(endpoints, Endpoint{URL: resolved, Method: method, Source: "openapi", Parameters: parameters})
		}
	}
	return endpoints
}
func resolveSpecURL(base, raw string) string {
	target, err := url.Parse(base)
	if err != nil {
		return ""
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	resolved := target.ResolveReference(reference)
	if !strings.EqualFold(target.Hostname(), resolved.Hostname()) || target.Port() != resolved.Port() {
		return ""
	}
	return resolved.String()
}
