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
	"github.com/khushi-nirsang/neoscanner/internal/payloads"
	"github.com/khushi-nirsang/neoscanner/internal/templates"
	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

type Scanner struct {
	Threads    int
	Results    *Results
	httpClient *utils.HTTPClient

	templates []*templates.Template
	mu        sync.RWMutex

	payloadCache map[string][]string
	payloadMu    sync.RWMutex
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
		payloadCache: make(
			map[string][]string,
		),
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

	sem := make(chan struct{}, s.Threads)
	var wg sync.WaitGroup

	for _, req := range tmpl.Requests {

		method := strings.ToUpper(strings.TrimSpace(req.Method))

		if method == "" {
			method = "GET"
		}

		requestPayloads, err := s.resolveRequestPayloads(req)

		if err != nil {
			color.Yellow(
				"Skipped payloads for template %s: %v",
				tmpl.ID,
				err,
			)
			continue
		}

		for _, rawPath := range req.Path {

			for _, payload := range requestPayloads {

				requestURL := buildRequestURL(
					target,
					rawPath,
					payload,
				)

				body := renderTemplateValue(
					req.Body,
					target,
					payload,
				)

				wg.Add(1)

				go func(requestURL, body, payload string) {
					defer wg.Done()

					sem <- struct{}{}
					defer func() {
						<-sem
					}()

					s.executeRequest(
						tmpl,
						req,
						target,
						method,
						requestURL,
						body,
						payload,
					)
				}(requestURL, body, payload)
			}
		}
	}

	wg.Wait()

}

func (s *Scanner) executeRequest(
	tmpl *templates.Template,
	req templates.Request,
	target string,
	method string,
	requestURL string,
	body string,
	payload string,
) {

	resp, err := s.httpClient.Do(
		method,
		requestURL,
		req.Headers,
		body,
	)

	if err != nil {
		color.Yellow(
			"Request failed %s %s: %v",
			method,
			requestURL,
			err,
		)
		return
	}

	if !s.matchMatchers(
		resp,
		req.Matchers,
		req.MatchersCondition,
		payload,
	) {
		return
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

}

func (s *Scanner) resolveRequestPayloads(
	req templates.Request,
) ([]string, error) {

	if len(req.Payloads) == 0 {
		return []string{""}, nil
	}

	resolved := make([]string, 0)
	seen := make(map[string]struct{})

	for _, payloadFile := range req.Payloads {

		payloadFile = strings.TrimSpace(payloadFile)

		if payloadFile == "" {
			continue
		}

		loaded, err := s.loadPayloadFile(payloadFile)

		if err != nil {
			return nil, err
		}

		for _, payload := range loaded {

			if _, exists := seen[payload]; exists {
				continue
			}

			seen[payload] = struct{}{}
			resolved = append(resolved, payload)
		}
	}

	if len(resolved) == 0 {
		return nil, fmt.Errorf("no payloads loaded")
	}

	return resolved, nil

}

func (s *Scanner) loadPayloadFile(
	payloadFile string,
) ([]string, error) {

	s.payloadMu.RLock()
	cached, ok := s.payloadCache[payloadFile]
	s.payloadMu.RUnlock()

	if ok {
		return cached, nil
	}

	loaded, err := payloads.Load(payloadFile)

	if err != nil {
		return nil, err
	}

	s.payloadMu.Lock()
	defer s.payloadMu.Unlock()

	if cached, ok := s.payloadCache[payloadFile]; ok {
		return cached, nil
	}

	s.payloadCache[payloadFile] = loaded

	return loaded, nil

}

func (s *Scanner) matchMatchers(
	resp *utils.Response,
	matchers []templates.Matcher,
	condition string,
	payload string,
) bool {

	if len(matchers) == 0 {
		return false
	}

	condition = strings.ToLower(strings.TrimSpace(condition))

	if condition == "and" {

		for _, matcher := range matchers {

			if !s.matchResponse(resp, matcher, payload) {
				return false
			}
		}

		return true
	}

	for _, matcher := range matchers {

		if s.matchResponse(resp, matcher, payload) {
			return true
		}
	}

	return false

}

func (s *Scanner) matchResponse(
	resp *utils.Response,
	matcher templates.Matcher,
	payload string,
) bool {

	var matched bool
	matcher = renderMatcher(matcher, payload)

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

func renderMatcher(
	matcher templates.Matcher,
	payload string,
) templates.Matcher {

	if payload == "" {
		return matcher
	}

	for i, word := range matcher.Words {
		matcher.Words[i] = strings.ReplaceAll(
			word,
			"{{payload}}",
			payload,
		)
	}

	quotedPayload := regexp.QuoteMeta(payload)

	for i, rx := range matcher.Regex {
		matcher.Regex[i] = strings.ReplaceAll(
			rx,
			"{{payload}}",
			quotedPayload,
		)
	}

	return matcher

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

func buildRequestURL(baseURL string, path string, payload string) string {

	path = renderURLTemplateValue(path, baseURL, payload)

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

func renderTemplateValue(value string, baseURL string, payload string) string {

	value = strings.ReplaceAll(
		value,
		"{{BaseURL}}",
		strings.TrimRight(baseURL, "/"),
	)

	return strings.ReplaceAll(value, "{{payload}}", payload)

}

func renderURLTemplateValue(value string, baseURL string, payload string) string {

	value = strings.ReplaceAll(
		value,
		"{{BaseURL}}",
		strings.TrimRight(baseURL, "/"),
	)

	if payload == "" {
		return strings.ReplaceAll(value, "{{payload}}", payload)
	}

	return strings.ReplaceAll(
		value,
		"{{payload}}",
		url.QueryEscape(payload),
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
