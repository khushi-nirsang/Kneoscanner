package engine

import (
"fmt"
"net/url"
"os"
"path/filepath"
"regexp"
"strings"
"sync"


"github.com/fatih/color"
"github.com/khushi-nirsang/neoscanner/internal/templates"
"github.com/khushi-nirsang/neoscanner/internal/utils"


)

type Scanner struct {
Threads    int
Results    *Results
httpClient *utils.HTTPClient

templates []*templates.Template
mu        sync.RWMutex

}

func NewScanner(threads int, timeout int) *Scanner {

if threads <= 0 {
	threads = 25
}

return &Scanner{
	Threads:    threads,
	Results:    NewResults(),
	httpClient: utils.NewHTTPClient(timeout),
	templates:  make([]*templates.Template, 0),
}

}

func (s *Scanner) LoadTemplates(templateDir string) error {

if templateDir == "" {
	templateDir = "templates"
}

if _, err := os.Stat(templateDir); err != nil {
	return fmt.Errorf("template directory not found: %s", templateDir)
}

count := 0

err := filepath.Walk(
	templateDir,
	func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return nil
		}

		if info == nil || info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(info.Name(), ".yaml") &&
			!strings.HasSuffix(info.Name(), ".yml") {
			return nil
		}

		tmpl, err := templates.LoadTemplate(path)
		if err != nil {

			color.Yellow(
				"Skipped template %s : %v",
				info.Name(),
				err,
			)

			return nil
		}

		if err := templates.ValidateTemplate(*tmpl); err != nil {

			color.Yellow(
				"Invalid template %s : %v",
				info.Name(),
				err,
			)

			return nil
		}

		s.templates = append(s.templates, tmpl)

		count++

		color.Green(
			"Loaded: %s [%s]",
			tmpl.Info.Name,
			tmpl.Info.Severity,
		)

		return nil
	},
)

if err != nil {
	return err
}

if count == 0 {
	return fmt.Errorf("no valid templates loaded")
}

color.Cyan("Templates Loaded: %d", count)

return nil

}

func (s *Scanner) StartScan(target string) {

target = normalizeTarget(target)

color.Cyan("Scanning: %s", target)

for _, tmpl := range s.templates {
	s.executeTemplate(tmpl, target)
}

}

func (s *Scanner) executeTemplate(
tmpl *templates.Template,
target string,
) {

for _, req := range tmpl.Requests {

	method := strings.ToUpper(strings.TrimSpace(req.Method))

	if method == "" {
		method = "GET"
	}

	for _, rawPath := range req.Path {

		requestURL := buildRequestURL(target, rawPath)

		resp, err := s.httpClient.Do(
			method,
			requestURL,
			req.Headers,
			renderTemplateValue(req.Body, target),
		)

		if err != nil {
			continue
		}

		if !s.matchMatchers(
			resp,
			req.Matchers,
			req.MatchersCondition,
		) {
			continue
		}

		s.Results.Add(
			ScanResult{
				Target:      target,
				TemplateID:  tmpl.ID,
				Name:        tmpl.Info.Name,
				Severity:    tmpl.Info.Severity,
				Matched:     true,
				Description: tmpl.Info.Description,
				MatchedURL:  requestURL,
				Method:      method,
				StatusCode:  resp.StatusCode,
			},
		)

		color.Red(
			"[%s] %s -> %s",
			strings.ToUpper(tmpl.Info.Severity),
			tmpl.Info.Name,
			requestURL,
		)

		return
	}
}

}

func (s *Scanner) matchMatchers(
resp *utils.Response,
matchers []templates.Matcher,
condition string,
) bool {

if len(matchers) == 0 {
	return false
}

condition = strings.ToLower(strings.TrimSpace(condition))

if condition == "and" {

	for _, matcher := range matchers {

		if !s.matchResponse(resp, matcher) {
			return false
		}
	}

	return true
}

for _, matcher := range matchers {

	if s.matchResponse(resp, matcher) {
		return true
	}
}

return false

}

func (s *Scanner) matchResponse(
resp *utils.Response,
matcher templates.Matcher,
) bool {

var matched bool

switch strings.ToLower(matcher.Type) {

case "word":

	matched = matchWords(
		responsePart(resp, matcher.Part),
		matcher.Words,
		matcher.Condition,
	)

case "status":

	for _, code := range matcher.Status {

		if resp.StatusCode == code {
			matched = true
			break
		}
	}

case "regex":

	for _, rx := range matcher.Regex {

		re, err := regexp.Compile(rx)

		if err != nil {
			continue
		}

		if re.MatchString(
			responsePart(resp, matcher.Part),
		) {
			matched = true
			break
		}
	}
}

if matcher.Negative {
	return !matched
}

return matched

}

func matchWords(
text string,
words []string,
condition string,
) bool {

if len(words) == 0 {
	return false
}

text = strings.ToLower(text)

if strings.ToLower(condition) == "and" {

	for _, word := range words {

		if !strings.Contains(
			text,
			strings.ToLower(word),
		) {
			return false
		}
	}

	return true
}

for _, word := range words {

	if strings.Contains(
		text,
		strings.ToLower(word),
	) {
		return true
	}
}

return false

}

func responsePart(
resp *utils.Response,
part string,
) string {

switch strings.ToLower(part) {

case "body":
	return resp.BodyContent

case "header":

	var b strings.Builder

	for k, v := range resp.Header {

		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(strings.Join(v, " "))
		b.WriteString("\n")
	}

	return b.String()

default:
	return resp.BodyContent
}

}

func normalizeTarget(target string) string {

target = strings.TrimSpace(target)

if target == "" {
	return target
}

if strings.HasPrefix(target, "http://") ||
	strings.HasPrefix(target, "https://") {
	return target
}

return "https://" + target

}

func buildRequestURL(baseURL string, path string) string {

path = renderTemplateValue(path, baseURL)

if strings.HasPrefix(path, "http://") ||
	strings.HasPrefix(path, "https://") {
	return path
}

base, err := url.Parse(baseURL)

if err != nil {
	return path
}

ref, err := url.Parse(path)

if err != nil {
	return path
}

return base.ResolveReference(ref).String()

}

func renderTemplateValue(value string, baseURL string) string {

return strings.ReplaceAll(
	value,
	"{{BaseURL}}",
	strings.TrimRight(baseURL, "/"),
)

}

func (s *Scanner) SaveResults(outputFile string) {

color.Cyan("Saving report...")

if err := s.Results.SaveJSON(outputFile); err != nil {
	color.Red("JSON save failed: %v", err)
}

htmlFile := htmlOutputPath(outputFile)

if err := s.Results.SaveHTML(htmlFile); err != nil {
	color.Red("HTML save failed: %v", err)
}

}

func htmlOutputPath(outputFile string) string {

ext := filepath.Ext(outputFile)

if ext == "" {
	return outputFile + ".html"
}

return strings.TrimSuffix(outputFile, ext) + ".html"

}