package discovery

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/khushi-nirsang/neoscanner/internal/utils"
	"golang.org/x/net/html"
)

type Options struct {
	MaxDepth        int
	MaxPages        int
	DiscoverScripts bool
	DiscoverOpenAPI bool
	DiscoverSitemap bool
	SeedEndpoints   []Endpoint
}

type Inventory struct {
	Target             string      `json:"target"`
	Pages              []Page      `json:"pages"`
	Endpoints          []Endpoint  `json:"endpoints"`
	Forms              []Form      `json:"forms"`
	Parameters         []Parameter `json:"parameters"`
	ParameterFilter    []string    `json:"parameter_filter,omitempty"`
	SelectedParameters []Parameter `json:"selected_parameters"`
	Scripts            []string    `json:"scripts"`
	APIs               []string    `json:"apis"`
}

type Page struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Depth      int    `json:"depth"`
}

type Endpoint struct {
	URL        string   `json:"url"`
	Method     string   `json:"method"`
	Source     string   `json:"source"`
	Parameters []string `json:"parameters,omitempty"`
}

type Form struct {
	Action   string            `json:"action"`
	Method   string            `json:"method"`
	Enctype  string            `json:"enctype,omitempty"`
	Fields   []string          `json:"fields,omitempty"`
	Defaults map[string]string `json:"defaults,omitempty"`
}

// Parameter records a discovered input location without retaining its value.
type Parameter struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Endpoint string `json:"endpoint"`
	Method   string `json:"method"`
	Source   string `json:"source"`
}

type Crawler struct {
	client  *utils.HTTPClient
	options Options
	ctx     context.Context
}

func New(client *utils.HTTPClient, options Options) *Crawler {
	return NewWithContext(context.Background(), client, options)
}

func NewWithContext(ctx context.Context, client *utils.HTTPClient, options Options) *Crawler {
	if ctx == nil {
		ctx = context.Background()
	}
	if options.MaxDepth < 0 {
		options.MaxDepth = 0
	}
	if options.MaxPages <= 0 {
		options.MaxPages = 100
	}
	return &Crawler{client: client, options: options, ctx: ctx}
}

func (c *Crawler) Crawl(target string) (Inventory, error) {
	root, err := url.Parse(target)
	if err != nil {
		return Inventory{}, err
	}

	inventory := Inventory{Target: target}
	queue := []queuedURL{{URL: root.String(), Depth: 0}}
	if c.options.DiscoverSitemap {
		for _, sitemapURL := range DiscoverSitemap(c.ctx, c.client, root.String()) {
			queue = append(queue, queuedURL{URL: sitemapURL, Depth: 1})
		}
	}
	visited := make(map[string]struct{})
	endpoints := make(map[string]Endpoint)
	scripts := make(map[string]struct{})
	apis := make(map[string]struct{})
	forms := make(map[string]Form)
	for _, endpoint := range c.options.SeedEndpoints {
		resolved, ok := resolveInScope(root, root.String(), endpoint.URL)
		if ok {
			addEndpoint(endpoints, resolved, endpoint.Method, endpoint.Source)
		}
	}

	for len(queue) > 0 && len(visited) < c.options.MaxPages {
		if c.ctx.Err() != nil {
			return inventory, c.ctx.Err()
		}
		current := queue[0]
		queue = queue[1:]
		if _, ok := visited[current.URL]; ok {
			continue
		}
		visited[current.URL] = struct{}{}

		response, requestErr := c.client.GetScopedContext(c.ctx, root.String(), current.URL)
		if requestErr != nil {
			continue
		}
		inventory.Pages = append(inventory.Pages, Page{URL: response.FinalURL, StatusCode: response.StatusCode, Depth: current.Depth})
		addEndpoint(endpoints, response.FinalURL, "GET", "crawl")

		if current.Depth >= c.options.MaxDepth || !isHTML(response.Header.Get("Content-Type"), response.BodyContent) {
			continue
		}

		parsed := parseDocument(response.FinalURL, response.BodyContent)
		for _, link := range parsed.Links {
			resolved, ok := resolveInScope(root, response.FinalURL, link)
			if !ok {
				continue
			}
			addEndpoint(endpoints, resolved, "GET", "link")
			if _, seen := visited[resolved]; !seen {
				queue = append(queue, queuedURL{URL: resolved, Depth: current.Depth + 1})
			}
		}
		for _, form := range parsed.Forms {
			if strings.TrimSpace(form.Action) == "" {
				form.Action = response.FinalURL
			}
			action, ok := resolveInScope(root, response.FinalURL, form.Action)
			if !ok {
				continue
			}
			form.Action = action
			if form.Method == "" {
				form.Method = "GET"
			}
			form.Method = strings.ToUpper(form.Method)
			forms[formKey(form)] = form
			addEndpoint(endpoints, action, form.Method, "form")
		}
		if c.options.DiscoverScripts {
			for _, script := range parsed.Scripts {
				resolved, ok := resolveInScope(root, response.FinalURL, script)
				if ok {
					scripts[resolved] = struct{}{}
					addEndpoint(endpoints, resolved, "GET", "script")
					// SPA routes are often only present inside bundled JavaScript.
					// Fetching is limited to same-origin assets and uses the same
					// context/scope policy as crawling.
					scriptResponse, scriptErr := c.client.GetScopedContext(c.ctx, root.String(), resolved)
					if scriptErr == nil {
						for _, api := range extractAPIRoutes(scriptResponse.BodyContent) {
							if apiURL, inScope := resolveInScope(root, resolved, api); inScope {
								apis[apiURL] = struct{}{}
								addEndpoint(endpoints, apiURL, "GET", "script-api")
							}
						}
					}
				}
			}
			for _, api := range parsed.APIs {
				resolved, ok := resolveInScope(root, response.FinalURL, api)
				if ok {
					apis[resolved] = struct{}{}
					addEndpoint(endpoints, resolved, "GET", "script-api")
				}
			}
		}
	}

	inventory.Endpoints = sortedEndpoints(endpoints)
	if c.options.DiscoverOpenAPI {
		for _, endpoint := range DiscoverOpenAPI(c.ctx, c.client, root.String()) {
			endpoints[endpoint.Method+" "+endpoint.URL] = endpoint
		}
		inventory.Endpoints = sortedEndpoints(endpoints)
	}
	inventory.Forms = sortedForms(forms)
	inventory.Parameters = collectParameters(inventory.Endpoints, inventory.Forms)
	inventory.SelectedParameters = append([]Parameter(nil), inventory.Parameters...)
	inventory.Scripts = sortedStrings(scripts)
	inventory.APIs = sortedStrings(apis)
	return inventory, nil
}

func extractAPIRoutes(script string) []string {
	matches := apiPath.FindAllStringSubmatch(script, -1)
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) > 1 && match[1] != "" {
			seen[match[1]] = struct{}{}
		}
	}
	return sortedStrings(seen)
}

func (inventory *Inventory) SelectParameters(names []string) {
	filter := normalizedNames(names)
	inventory.ParameterFilter = filter
	if len(filter) == 0 {
		inventory.SelectedParameters = append([]Parameter(nil), inventory.Parameters...)
		return
	}
	allowed := make(map[string]struct{}, len(filter))
	for _, name := range filter {
		allowed[name] = struct{}{}
	}
	selected := make([]Parameter, 0)
	for _, parameter := range inventory.Parameters {
		if _, ok := allowed[strings.ToLower(parameter.Name)]; ok {
			selected = append(selected, parameter)
		}
	}
	inventory.SelectedParameters = selected
}

type queuedURL struct {
	URL   string
	Depth int
}
type parsedDocument struct {
	Links   []string
	Forms   []Form
	Scripts []string
	APIs    []string
}

var apiPath = regexp.MustCompile(`(?i)["'](/(?:api|v[0-9]+|graphql)[^"'\s]*)["']`)

func parseDocument(baseURL, document string) parsedDocument {
	result := parsedDocument{}
	tokenizer := html.NewTokenizer(strings.NewReader(document))
	var currentForm *Form
	inScript := false
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			return result
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			name := strings.ToLower(token.Data)
			attributes := attributeMap(token.Attr)
			switch name {
			case "a", "area", "link":
				if href := attributes["href"]; href != "" {
					result.Links = append(result.Links, href)
				}
			case "form":
				currentForm = &Form{Action: attributes["action"], Method: attributes["method"], Enctype: attributes["enctype"], Defaults: make(map[string]string)}
			case "input", "textarea", "select", "button":
				if currentForm != nil && attributes["name"] != "" {
					field := attributes["name"]
					currentForm.Fields = append(currentForm.Fields, field)
					currentForm.Defaults[field] = attributes["value"]
				}
			case "script":
				inScript = true
				if src := attributes["src"]; src != "" {
					result.Scripts = append(result.Scripts, src)
				}
			}
		case html.EndTagToken:
			name := strings.ToLower(tokenizer.Token().Data)
			if name == "form" && currentForm != nil {
				currentForm.Fields = uniqueSorted(currentForm.Fields)
				result.Forms = append(result.Forms, *currentForm)
				currentForm = nil
			}
			if name == "script" {
				inScript = false
			}
		case html.TextToken:
			if inScript {
				for _, match := range apiPath.FindAllStringSubmatch(string(tokenizer.Raw()), -1) {
					result.APIs = append(result.APIs, match[1])
				}
			}
		}
	}
}

func attributeMap(attributes []html.Attribute) map[string]string {
	result := make(map[string]string, len(attributes))
	for _, attribute := range attributes {
		result[strings.ToLower(attribute.Key)] = strings.TrimSpace(attribute.Val)
	}
	return result
}

func resolveInScope(root *url.URL, baseURL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(strings.ToLower(raw), "javascript:") || strings.HasPrefix(strings.ToLower(raw), "data:") {
		return "", false
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", false
	}
	reference, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(reference)
	if !strings.EqualFold(root.Hostname(), resolved.Hostname()) || root.Port() != resolved.Port() || (resolved.Scheme != "http" && resolved.Scheme != "https") {
		return "", false
	}
	resolved.Fragment = ""
	return resolved.String(), true
}

func isHTML(contentType, body string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html") || strings.Contains(strings.ToLower(body), "<html") || strings.Contains(strings.ToLower(body), "<form")
}
func addEndpoint(endpoints map[string]Endpoint, rawURL, method, source string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	parameters := make([]string, 0, len(parsed.Query()))
	for key := range parsed.Query() {
		parameters = append(parameters, key)
	}
	sort.Strings(parameters)
	key := method + " " + parsed.String()
	if _, exists := endpoints[key]; !exists {
		endpoints[key] = Endpoint{URL: parsed.String(), Method: method, Source: source, Parameters: parameters}
	}
}
func formKey(form Form) string {
	return form.Method + " " + form.Action + " " + strings.Join(form.Fields, ",")
}
func sortedEndpoints(values map[string]Endpoint) []Endpoint {
	result := make([]Endpoint, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].URL == result[j].URL {
			return result[i].Method < result[j].Method
		}
		return result[i].URL < result[j].URL
	})
	return result
}
func sortedForms(values map[string]Form) []Form {
	result := make([]Form, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return formKey(result[i]) < formKey(result[j]) })
	return result
}
func sortedStrings(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{})
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	return sortedStrings(seen)
}

func collectParameters(endpoints []Endpoint, forms []Form) []Parameter {
	seen := make(map[string]Parameter)
	for _, endpoint := range endpoints {
		for _, name := range endpoint.Parameters {
			parameter := Parameter{Name: name, Location: "query", Endpoint: endpoint.URL, Method: endpoint.Method, Source: endpoint.Source}
			seen[parameterKey(parameter)] = parameter
		}
	}
	for _, form := range forms {
		for _, name := range form.Fields {
			parameter := Parameter{Name: name, Location: "form", Endpoint: form.Action, Method: form.Method, Source: "form"}
			seen[parameterKey(parameter)] = parameter
		}
	}
	parameters := make([]Parameter, 0, len(seen))
	for _, parameter := range seen {
		parameters = append(parameters, parameter)
	}
	sort.Slice(parameters, func(i, j int) bool {
		if parameters[i].Endpoint == parameters[j].Endpoint {
			if parameters[i].Location == parameters[j].Location {
				return parameters[i].Name < parameters[j].Name
			}
			return parameters[i].Location < parameters[j].Location
		}
		return parameters[i].Endpoint < parameters[j].Endpoint
	})
	return parameters
}

func parameterKey(parameter Parameter) string {
	return parameter.Method + "|" + parameter.Endpoint + "|" + parameter.Location + "|" + parameter.Name
}

func normalizedNames(names []string) []string {
	seen := make(map[string]struct{})
	for _, namesValue := range names {
		for _, name := range strings.Split(namesValue, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				seen[name] = struct{}{}
			}
		}
	}
	return sortedStrings(seen)
}
