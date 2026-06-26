package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/khushi-nirsang/neoscanner/internal/discovery"
	"github.com/khushi-nirsang/neoscanner/internal/fingerprint"
	"github.com/khushi-nirsang/neoscanner/internal/payloads"
	"github.com/khushi-nirsang/neoscanner/internal/templates"
	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

type Scanner struct {
	Threads                int
	Results                *Results
	httpClient             *utils.HTTPClient
	allowExternalURLs      bool
	discoveryOptions       discovery.Options
	parameterFilter        []string
	activeParameterTesting bool
	maxParameterMutations  int
	payloadsPerParameter   int
	activePostFormTesting  bool
	maxPostFormMutations   int
	scanProfile            string
	evidenceMaxBytes       int64
	redactSensitiveData    bool
	ctx                    context.Context
	cancel                 context.CancelFunc
	eventSink              func(ScanEvent)

	templates []*templates.Template
	mu        sync.RWMutex

	payloadCache map[string][]string
	payloadMu    sync.RWMutex
}

// ScanEvent is a structured, UI-safe progress message emitted by the scanner.
type ScanEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Target    string    `json:"target,omitempty"`
	Message   string    `json:"message"`
	FindingID string    `json:"finding_id,omitempty"`
}

type DiscoveryOptions = discovery.Options

func NewScanner(threads int, timeout int) *Scanner {
	options := utils.DefaultHTTPOptions()
	options.Timeout = time.Duration(timeout) * time.Second
	return NewScannerWithOptions(threads, options, false)
}

func NewScannerWithOptions(threads int, options utils.HTTPOptions, allowExternalURLs bool) *Scanner {

	if threads <= 0 {
		threads = 25
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanner := &Scanner{
		Threads:             threads,
		Results:             NewResults(),
		httpClient:          utils.NewHTTPClientWithOptions(options),
		allowExternalURLs:   allowExternalURLs,
		scanProfile:         "safe",
		evidenceMaxBytes:    64 * 1024,
		redactSensitiveData: true,
		ctx:                 ctx,
		cancel:              cancel,
		templates:           make([]*templates.Template, 0),
		payloadCache: make(
			map[string][]string,
		),
	}
	scanner.httpClient.SetMaxConcurrentRequests(threads)
	return scanner

}

// ConfigureRuntime connects the scanner to its owner (CLI or GUI). Cancelling
// the supplied context stops in-flight HTTP work and prevents queued probes.
func (s *Scanner) ConfigureRuntime(ctx context.Context, sink func(ScanEvent)) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.cancel != nil {
		s.cancel()
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.eventSink = sink
}

func (s *Scanner) Cancel() {
	if s.cancel != nil {
		s.cancel()
		s.emit("scan.cancelled", "", "Scan cancellation requested", "")
	}
}
func (s *Scanner) emit(kind, target, message, findingID string) {
	if s.eventSink != nil {
		s.eventSink(ScanEvent{Timestamp: time.Now(), Type: kind, Target: target, Message: message, FindingID: findingID})
	}
}

func (s *Scanner) ConfigureDiscovery(options DiscoveryOptions) {
	s.discoveryOptions = options
}

func (s *Scanner) ConfigureParameterFilter(parameters []string) {
	s.parameterFilter = append([]string(nil), parameters...)
}

func (s *Scanner) ConfigureActiveParameterTesting(enabled bool, maxMutations, payloadsPerParameter int) {
	s.activeParameterTesting = enabled
	s.maxParameterMutations = maxMutations
	s.payloadsPerParameter = payloadsPerParameter
}

func (s *Scanner) ConfigurePostFormTesting(enabled bool, maxMutations int) {
	s.activePostFormTesting = enabled
	s.maxPostFormMutations = maxMutations
}

// ConfigureEvidence limits persisted HTTP transcripts. Sensitive headers and
// common credential fields are redacted by default.
func (s *Scanner) ConfigureEvidence(maxBytes int64, redactSensitiveData bool) {
	if maxBytes > 0 {
		s.evidenceMaxBytes = maxBytes
	}
	s.redactSensitiveData = redactSensitiveData
}

// ConfigureScanProfile controls request risk. Safe is the default and avoids
// mutation probes; active requires an explicit authorization acknowledgement;
// intrusive additionally permits state-changing templates.
func (s *Scanner) ConfigureScanProfile(profile string) {
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile != "passive" && profile != "safe" && profile != "active" && profile != "intrusive" {
		profile = "safe"
	}
	s.scanProfile = profile
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

			if tmpl.Disabled {
				color.Cyan("Skipped disabled template: %s", tmpl.ID)
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
	if s.ctx.Err() != nil {
		return
	}

	target = normalizeTarget(target)
	s.emit("scan.started", target, "Scanning target", "")

	color.Cyan("Scanning: %s", target)
	s.scanSecurityConfiguration(target)
	discoveryDrivenInputs := false

	if s.discoveryOptions.MaxPages > 0 {
		inventory, err := discovery.NewWithContext(s.ctx, s.httpClient, s.discoveryOptions).Crawl(target)
		if err != nil {
			color.Yellow("Discovery failed for %s: %v", target, err)
		} else {
			inventory.SelectParameters(s.parameterFilter)
			s.Results.AddDiscovery(inventory)
			color.Cyan("Discovered: %d pages, %d endpoints, %d forms, %d selected parameters", len(inventory.Pages), len(inventory.Endpoints), len(inventory.Forms), len(inventory.SelectedParameters))
			s.scanDiscoveredCSRF(target, inventory)
			if s.activeParameterTesting && s.profileAtLeast("active") {
				s.scanDiscoveredQueryParameters(target, inventory)
				if len(inventory.SelectedParameters) > 0 {
					discoveryDrivenInputs = true
				}
			}
			if s.activePostFormTesting && s.profileAtLeast("active") {
				if len(inventory.SelectedParameters) > 0 {
					s.scanDiscoveredPOSTForms(target, inventory)
					discoveryDrivenInputs = true
				} else {
					color.Yellow("Skipped POST form testing: no POST form parameters discovered")
				}
			}
		}
	}

	for _, tmpl := range s.templates {
		if s.ctx.Err() != nil {
			break
		}
		// Prefer discovered inputs for mutation checks. In active/intrusive scans,
		// fall back to template paths only when discovery found nothing useful;
		// this keeps lab/demo targets testable without changing safe mode.
		if isDiscoveryDrivenTemplate(tmpl.ID) {
			if !s.profileAtLeast("active") {
				s.emit("template.skipped", target, "Skipped active template in safe/passive profile: "+tmpl.ID, "")
				continue
			}
			if discoveryDrivenInputs {
				s.emit("template.skipped", target, "Skipped template fallback because discovered inputs were tested: "+tmpl.ID, "")
				continue
			}
			color.Yellow("No discovered inputs for %s; running template fallback paths", tmpl.ID)
		}
		if !s.templateAllowed(tmpl) {
			color.Cyan("Skipped %s: requires %s profile", tmpl.Info.Name, templateRisk(tmpl))
			continue
		}
		s.executeTemplate(tmpl, target)
	}
	s.emit("scan.completed", target, "Target scan completed", "")

}

func (s *Scanner) profileAtLeast(required string) bool {
	ranks := map[string]int{"passive": 0, "safe": 1, "active": 2, "intrusive": 3}
	return ranks[s.scanProfile] >= ranks[required]
}

func (s *Scanner) templateAllowed(tmpl *templates.Template) bool {
	return s.profileAtLeast(templateRisk(tmpl))
}

func templateRisk(tmpl *templates.Template) string {
	if risk := strings.ToLower(strings.TrimSpace(tmpl.Info.Risk)); risk != "" {
		return risk
	}
	switch tmpl.ID {
	case "race-condition", "mass-assignment", "privilege-escalation", "command-injection":
		return "intrusive"
	case "authentication-bypass", "weak-authentication", "xxe-detection", "insecure-deserialization", "csrf-detection", "xss-probe", "sql-injection", "ssti-detection", "ssti-advanced", "ssrf-probe", "open-redirect", "ldap-injection", "local-file-inclusion", "remote-file-inclusion", "path-traversal":
		return "active"
	}
	for _, request := range tmpl.Requests {
		if strings.ToUpper(request.Method) != http.MethodGet && strings.ToUpper(request.Method) != http.MethodHead {
			return "active"
		}
	}
	return "safe"
}

func (s *Scanner) templateResult(tmpl *templates.Template, target, method, matchedURL, parameter, payload, body string, response *utils.Response, confidence string) ScanResult {
	if confidence == "" {
		confidence = strings.ToLower(strings.TrimSpace(tmpl.Info.Confidence))
	}
	if confidence == "" {
		confidence = "potential"
	}
	return ScanResult{
		Target: target, TemplateID: tmpl.ID, TemplateAuthor: tmpl.Info.Author,
		Name: tmpl.Info.Name, Severity: tmpl.Info.Severity, Description: tmpl.Info.Description,
		Confidence: confidence, CWE: append([]string(nil), tmpl.Info.CWE...), CVSSScore: tmpl.Info.CVSSScore,
		CVSSVector: tmpl.Info.CVSSVector, Impact: tmpl.Info.Impact, CVEs: append([]string(nil), tmpl.Info.CVEs...),
		Technologies: technologyFingerprint(response),
		References:   append([]string(nil), tmpl.Info.References...), Remediation: tmpl.Info.Remediation,
		Matched: true, MatchedURL: matchedURL, Method: method, Parameter: parameter, Payload: payload,
		Request: s.requestTranscript(method, matchedURL, body, response), Response: s.transcript(method, matchedURL, body, response),
	}
}

func technologyFingerprint(response *utils.Response) []string {
	if response == nil {
		return nil
	}
	return fingerprint.Detect(response).Technologies
}

// scanDiscoveredCSRF inspects the forms the crawler actually found instead of
// guessing endpoint names. It is intentionally reported as potential: absence
// of a visible token is strong triage evidence, but not proof that a server
// does not use another CSRF defense.
func (s *Scanner) scanDiscoveredCSRF(target string, inventory discovery.Inventory) {
	for _, form := range inventory.Forms {
		if form.Method != http.MethodPost || hasCSRFField(form.Fields) {
			continue
		}
		evidence := []string{
			"discovered POST form has no CSRF-token-like input",
			"form fields: " + strings.Join(form.Fields, ", "),
		}
		if s.Results.Add(ScanResult{
			Target:        target,
			TemplateID:    "csrf-discovered-form",
			Name:          "Potential Missing CSRF Protection",
			Severity:      "medium",
			OWASPCategory: "insecure-design",
			Confidence:    "potential",
			Matched:       true,
			Description:   "A discovered state-changing POST form has no visible anti-CSRF token field.",
			MatchedURL:    form.Action,
			FinalURL:      form.Action,
			Method:        http.MethodPost,
			Evidence:      evidence,
		}) {
			color.Red("[MEDIUM] Potential Missing CSRF Protection (discovered POST form) -> %s (proof: no CSRF-token-like input)", form.Action)
		}
	}
}

func hasCSRFField(fields []string) bool {
	for _, field := range fields {
		name := strings.ToLower(field)
		if strings.Contains(name, "csrf") || strings.Contains(name, "xsrf") || strings.Contains(name, "authenticity") || strings.Contains(name, "nonce") || strings.Contains(name, "token") {
			return true
		}
	}
	return false
}

func (s *Scanner) scanSecurityConfiguration(target string) {
	resp, err := s.httpClient.GetScopedContext(s.ctx, target, target)
	if err != nil {
		color.Yellow("Passive security checks failed for %s: %v", target, err)
		return
	}
	checks := []struct {
		header      string
		name        string
		description string
		severity    string
	}{
		{"Content-Security-Policy", "Missing Content Security Policy", "The response lacks a Content-Security-Policy header.", "low"},
		{"X-Content-Type-Options", "Missing X-Content-Type-Options", "The response lacks X-Content-Type-Options: nosniff.", "low"},
		{"X-Frame-Options", "Missing Clickjacking Protection", "The response lacks X-Frame-Options protection.", "low"},
		{"Referrer-Policy", "Missing Referrer Policy", "The response lacks a Referrer-Policy header.", "info"},
	}
	if strings.HasPrefix(strings.ToLower(target), "https://") {
		checks = append(checks, struct{ header, name, description, severity string }{"Strict-Transport-Security", "Missing HTTP Strict Transport Security", "The HTTPS response lacks a Strict-Transport-Security header.", "low"})
	}
	for _, check := range checks {
		if resp.Header.Get(check.header) == "" {
			s.addPassiveFinding(target, resp, "security-misconfiguration", check.name, check.description, check.severity)
		}
	}
	for _, cookie := range resp.Cookies() {
		name := strings.ToLower(cookie.Name)
		if !strings.Contains(name, "session") && !strings.Contains(name, "auth") && !strings.Contains(name, "token") && !strings.Contains(name, "sid") {
			continue
		}
		if !cookie.HttpOnly {
			s.addPassiveFinding(target, resp, "identification-and-authentication-failures", "Session Cookie Missing HttpOnly", "Session-like cookie "+cookie.Name+" lacks the HttpOnly flag.", "medium")
		}
		if strings.HasPrefix(strings.ToLower(target), "https://") && !cookie.Secure {
			s.addPassiveFinding(target, resp, "cryptographic-failures", "Session Cookie Missing Secure", "Session-like cookie "+cookie.Name+" lacks the Secure flag over HTTPS.", "medium")
		}
	}
}

func (s *Scanner) addPassiveFinding(target string, resp *utils.Response, category, name, description, severity string) {
	evidence := []string{fmt.Sprintf("response status: %d", resp.StatusCode), "required protection header is absent"}
	if s.Results.Add(ScanResult{Target: target, TemplateID: "passive-" + strings.ToLower(strings.ReplaceAll(name, " ", "-")), Name: name, Severity: severity, OWASPCategory: category, Confidence: "confirmed", Matched: true, Description: description, MatchedURL: target, FinalURL: resp.FinalURL, Method: http.MethodGet, StatusCode: resp.StatusCode, BodySize: resp.BodySize, Truncated: resp.Truncated, Attempts: resp.Attempts, Technologies: technologyFingerprint(resp), Evidence: evidence, Request: s.requestTranscript(http.MethodGet, target, "", resp), Response: s.transcript(http.MethodGet, target, "", resp)}) {
		color.Red("[%s] %s (passive) -> %s (proof: required response header is absent)", strings.ToUpper(severity), name, target)
	}
}

func isDiscoveryDrivenTemplate(templateID string) bool {
	switch templateID {
	case "xss-probe", "sql-injection", "ssti-detection", "ssrf-probe", "open-redirect", "local-file-inclusion", "remote-file-inclusion", "path-traversal", "command-injection":
		return true
	default:
		return false
	}
}

func (s *Scanner) scanDiscoveredQueryParameters(target string, inventory discovery.Inventory) {
	maxMutations := s.maxParameterMutations
	if maxMutations <= 0 {
		maxMutations = 200
	}
	payloadLimit := s.payloadsPerParameter
	if payloadLimit <= 0 {
		payloadLimit = 5
	}

	seen := make(map[string]struct{})
	mutations := 0
	forms := make(map[string]discovery.Form, len(inventory.Forms))
	for _, form := range inventory.Forms {
		forms[form.Method+"|"+form.Action] = form
	}
	for _, parameter := range prioritizeParameters(inventory.SelectedParameters) {
		if parameter.Method != "GET" || (parameter.Location != "query" && parameter.Location != "form") || mutations >= maxMutations {
			continue
		}
		key := parameter.Endpoint + "|" + parameter.Name
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		baselineURL := parameter.Endpoint
		if parameter.Location == "form" {
			form, exists := forms[parameter.Method+"|"+parameter.Endpoint]
			if !exists {
				continue
			}
			baselineURL = buildFormRequestURL(form)
		}
		baseline, err := s.httpClient.GetScopedContext(s.ctx, target, baselineURL)
		if err != nil {
			continue
		}

		for _, tmpl := range s.templates {
			if !isDiscoveryDrivenTemplate(tmpl.ID) || len(tmpl.Requests) == 0 {
				continue
			}
			if !s.templateAllowed(tmpl) {
				continue
			}
			req := tmpl.Requests[0]
			payloads, err := s.resolveRequestPayloads(req)
			if err != nil {
				continue
			}
			for index, payload := range payloads {
				if index >= payloadLimit || mutations >= maxMutations {
					break
				}
				mutatedURL, ok := replaceQueryParameter(baselineURL, parameter.Name, payload)
				if !ok || !s.allowExternalURLs && !isInScope(target, mutatedURL) {
					continue
				}
				response, err := s.httpClient.GetScopedContext(s.ctx, target, mutatedURL)
				mutations++
				if err != nil || s.matchMatchers(baseline, req.Matchers, req.MatchersCondition, payload) || !s.matchMatchers(response, req.Matchers, req.MatchersCondition, payload) {
					continue
				}
				if ok, _ := validateTemplateFinding(tmpl.ID, target, payload, response); !ok {
					continue
				}
				evidence := append(mutationEvidenceIntro(tmpl.ID), s.matcherEvidence(response, req.Matchers, payload)...)
				evidence = append(evidence, s.extractorEvidence(response, req.Extractors)...)
				finding := s.templateResult(tmpl, target, http.MethodGet, mutatedURL, parameter.Name, payload, "", response, "firm")
				finding.FinalURL, finding.StatusCode, finding.BodySize, finding.Truncated, finding.Attempts, finding.Evidence = response.FinalURL, response.StatusCode, response.BodySize, response.Truncated, response.Attempts, evidence
				finding.Baseline = s.transcript(http.MethodGet, baselineURL, "", baseline)
				if s.Results.Add(finding) {
					color.Red("[%s] %s (%s %s parameter) -> %s (payload: %s; proof: payload was absent from the baseline and reflected in the response)", strings.ToUpper(tmpl.Info.Severity), tmpl.Info.Name, parameter.Name, parameter.Location, mutatedURL, payload)
				}
			}
		}
	}
	color.Cyan("Active GET query/form parameter testing completed: %d mutations", mutations)
}

func (s *Scanner) scanDiscoveredPOSTForms(target string, inventory discovery.Inventory) {
	maxMutations := s.maxPostFormMutations
	if maxMutations <= 0 {
		maxMutations = 50
	}
	payloadLimit := s.payloadsPerParameter
	if payloadLimit <= 0 {
		payloadLimit = 5
	}

	forms := make(map[string]discovery.Form, len(inventory.Forms))
	for _, form := range inventory.Forms {
		if form.Method == http.MethodPost && isURLEncodedForm(form.Enctype) {
			forms[form.Method+"|"+form.Action] = form
		}
	}
	mutations := 0
	for _, parameter := range prioritizeParameters(inventory.SelectedParameters) {
		if parameter.Location != "form" || parameter.Method != http.MethodPost || mutations >= maxMutations {
			continue
		}
		form, exists := forms[parameter.Method+"|"+parameter.Endpoint]
		if !exists || (!s.allowExternalURLs && !isInScope(target, form.Action)) {
			continue
		}
		baseline, err := s.httpClient.DoWithOptionsContext(s.ctx, http.MethodPost, form.Action, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, buildFormBody(form, "", ""), utils.RequestOptions{ScopeURL: target})
		if err != nil {
			continue
		}
		for _, tmpl := range s.templates {
			if !isDiscoveryDrivenTemplate(tmpl.ID) || len(tmpl.Requests) == 0 {
				continue
			}
			if !s.templateAllowed(tmpl) {
				continue
			}
			req := tmpl.Requests[0]
			payloads, err := s.resolveRequestPayloads(req)
			if err != nil {
				continue
			}
			for index, payload := range payloads {
				if index >= payloadLimit || mutations >= maxMutations {
					break
				}
				response, err := s.httpClient.DoWithOptionsContext(s.ctx, http.MethodPost, form.Action, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, buildFormBody(form, parameter.Name, payload), utils.RequestOptions{ScopeURL: target})
				mutations++
				if err != nil || s.matchMatchers(baseline, req.Matchers, req.MatchersCondition, payload) || !s.matchMatchers(response, req.Matchers, req.MatchersCondition, payload) {
					continue
				}
				if ok, _ := validateTemplateFinding(tmpl.ID, target, payload, response); !ok {
					continue
				}
				evidence := append(mutationEvidenceIntro(tmpl.ID), s.matcherEvidence(response, req.Matchers, payload)...)
				evidence = append(evidence, s.extractorEvidence(response, req.Extractors)...)
				body := buildFormBody(form, parameter.Name, payload)
				finding := s.templateResult(tmpl, target, http.MethodPost, form.Action, parameter.Name, payload, body, response, "firm")
				finding.FinalURL, finding.StatusCode, finding.BodySize, finding.Truncated, finding.Attempts, finding.Evidence = response.FinalURL, response.StatusCode, response.BodySize, response.Truncated, response.Attempts, evidence
				finding.Baseline = s.transcript(http.MethodPost, form.Action, buildFormBody(form, "", ""), baseline)
				if s.Results.Add(finding) {
					color.Red("[%s] %s (%s POST form parameter) -> %s (payload: %s; proof: payload was absent from the baseline)", strings.ToUpper(tmpl.Info.Severity), tmpl.Info.Name, parameter.Name, form.Action, payload)
				}
			}
		}
	}
	color.Cyan("Active POST form parameter testing completed: %d mutations", mutations)
}

// prioritizeParameters spreads a bounded mutation budget across distinct input
// names before retesting the same name on additional endpoints.
func prioritizeParameters(parameters []discovery.Parameter) []discovery.Parameter {
	groups := make(map[string][]discovery.Parameter)
	keys := make([]string, 0)
	for _, parameter := range parameters {
		key := strings.ToLower(parameter.Location + "|" + parameter.Name)
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], parameter)
	}
	sort.Strings(keys)
	for _, key := range keys {
		sort.Slice(groups[key], func(i, j int) bool { return groups[key][i].Endpoint < groups[key][j].Endpoint })
	}
	ordered := make([]discovery.Parameter, 0, len(parameters))
	for index := 0; ; index++ {
		added := false
		for _, key := range keys {
			if index < len(groups[key]) {
				ordered = append(ordered, groups[key][index])
				added = true
			}
		}
		if !added {
			return ordered
		}
	}
}

func isURLEncodedForm(enctype string) bool {
	enctype = strings.ToLower(strings.TrimSpace(enctype))
	return enctype == "" || enctype == "application/x-www-form-urlencoded"
}

func buildFormBody(form discovery.Form, mutatedName, payload string) string {
	values := url.Values{}
	for _, field := range form.Fields {
		values.Set(field, form.Defaults[field])
	}
	if mutatedName != "" {
		values.Set(mutatedName, payload)
	}
	return values.Encode()
}

func replaceQueryParameter(rawURL, parameter, payload string) (string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	query := parsed.Query()
	// OpenAPI describes valid query inputs without necessarily providing a
	// sample value in the endpoint URL, so an absent documented parameter is a
	// valid mutation target.
	query.Set(parameter, payload)
	parsed.RawQuery = query.Encode()
	return parsed.String(), true
}

func buildFormRequestURL(form discovery.Form) string {
	parsed, err := url.Parse(form.Action)
	if err != nil {
		return form.Action
	}
	query := parsed.Query()
	for _, field := range form.Fields {
		if _, exists := query[field]; !exists {
			query.Set(field, form.Defaults[field])
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
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
	if !s.allowExternalURLs && !isInScope(target, requestURL) {
		color.Yellow("Skipped out-of-scope request %s", requestURL)
		return
	}

	headers := renderHeaders(req.Headers, target, payload)
	requestOptions := utils.RequestOptions{FollowRedirects: req.Redirects}
	if req.Timeout > 0 {
		requestOptions.Timeout = time.Duration(req.Timeout) * time.Second
	}

	s.emit("request.started", target, method+" "+requestURL, "")
	requestOptions.ScopeURL = target
	if s.allowExternalURLs && !isInScope(target, requestURL) {
		requestOptions.SkipDefaultHeaders = true
	}
	resp, err := s.httpClient.DoWithOptionsContext(s.ctx,
		method,
		requestURL,
		headers,
		body,
		requestOptions,
	)

	if err != nil {
		s.emit("request.failed", target, method+" "+requestURL+": "+err.Error(), "")
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
	if ok, reason := validateTemplateFinding(tmpl.ID, target, payload, resp); !ok {
		s.emit("finding.suppressed", target, fmt.Sprintf("Suppressed weak %s signal: %s", tmpl.ID, reason), "")
		return
	}
	// Login pages frequently contain words such as "personal information".
	// A request that ends back on a login endpoint is a failed authentication
	// attempt, never evidence of an authentication bypass.
	if tmpl.ID == "authentication-bypass" && isLoginRoute(resp.FinalURL) {
		return
	}

	evidence := s.matcherEvidence(resp, req.Matchers, payload)
	evidence = append(evidence, s.extractorEvidence(resp, req.Extractors)...)
	if tmpl.ID == "authentication-bypass" {
		evidence = append([]string{"authentication attempt reached: " + resp.FinalURL}, evidence...)
	}
	finding := s.templateResult(tmpl, target, method, requestURL, "", payload, body, resp, "")
	finding.FinalURL, finding.StatusCode, finding.BodySize, finding.Truncated, finding.Attempts, finding.Evidence = resp.FinalURL, resp.StatusCode, resp.BodySize, resp.Truncated, resp.Attempts, evidence
	if !s.Results.Add(finding) {
		return
	}
	s.emit("finding.created", target, finding.Name, finding.FindingID)

	payloadNotice := ""
	if payload != "" {
		payloadNotice = fmt.Sprintf(" (payload: %s)", payload)
	}
	if len(evidence) > 0 {
		payloadNotice += fmt.Sprintf(" (proof: %s)", evidence[0])
	}

	color.Red(
		"[%s] %s -> %s%s",
		strings.ToUpper(tmpl.Info.Severity),
		tmpl.Info.Name,
		requestURL,
		payloadNotice,
	)

}

// matcherEvidence turns the response checks that produced a finding into
// concise, reviewable proof. It deliberately records values, not whole pages.
func (s *Scanner) matcherEvidence(resp *utils.Response, matchers []templates.Matcher, payload string) []string {
	evidence := make([]string, 0, len(matchers))
	for _, raw := range matchers {
		matcher := renderMatcher(raw, payload)
		if !s.matchResponse(resp, matcher, "") {
			continue
		}
		switch strings.ToLower(matcher.Type) {
		case "status":
			evidence = append(evidence, fmt.Sprintf("response status: %d", resp.StatusCode))
		case "word":
			if matcher.Negative {
				evidence = append(evidence, "response lacks expected protection marker")
				continue
			}
			for _, word := range matcher.Words {
				if strings.Contains(strings.ToLower(responsePart(resp, matcher.Part)), strings.ToLower(word)) {
					evidence = append(evidence, fmt.Sprintf("%s contains %q", evidencePart(matcher.Part), word))
					break
				}
			}
		case "regex":
			if matcher.Negative {
				evidence = append(evidence, "response lacks a prohibited response pattern")
				continue
			}
			for _, pattern := range matcher.Regex {
				re, err := regexp.Compile(pattern)
				if err == nil && re.MatchString(responsePart(resp, matcher.Part)) {
					evidence = append(evidence, fmt.Sprintf("%s matched %q", evidencePart(matcher.Part), pattern))
					break
				}
			}
		}
	}
	return evidence
}

// extractorEvidence adds concise extracted proof snippets without copying whole
// pages. This gives analysts the "show me why" signal that mature scanners are
// judged on.
func (s *Scanner) extractorEvidence(resp *utils.Response, extractors []templates.Extractor) []string {
	evidence := make([]string, 0, len(extractors))
	for _, extractor := range extractors {
		if strings.ToLower(strings.TrimSpace(extractor.Type)) != "regex" {
			continue
		}
		source := responsePart(resp, extractor.Part)
		for _, pattern := range extractor.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			match := re.FindString(source)
			if match == "" {
				continue
			}
			if len(match) > 180 {
				match = match[:180] + "..."
			}
			evidence = append(evidence, fmt.Sprintf("%s extracted %q", evidencePart(extractor.Part), match))
			break
		}
	}
	return evidence
}

func validateTemplateFinding(templateID, target, payload string, resp *utils.Response) (bool, string) {
	if resp == nil {
		return false, "no response captured"
	}
	switch templateID {
	case "open-redirect":
		return validateOpenRedirect(target, payload, resp)
	case "local-file-inclusion", "path-traversal":
		if hasStrongFileDisclosureSignal(resp.BodyContent) {
			return true, ""
		}
		return false, "response only matched a generic file/server word, not a strong file-disclosure marker"
	case "command-injection":
		if hasCommandExecutionSignal(resp.BodyContent) {
			return true, ""
		}
		return false, "response did not contain a strong command-execution marker"
	default:
		return true, ""
	}
}

func mutationEvidenceIntro(templateID string) []string {
	base := []string{"baseline response did not match the vulnerability signature"}
	switch templateID {
	case "xss-probe":
		return append(base, "mutated response reflected the injected payload")
	case "open-redirect":
		return append(base, "mutated response redirected to the injected external host")
	case "local-file-inclusion", "remote-file-inclusion", "path-traversal":
		return append(base, "mutated response exposed a file-disclosure signature")
	case "command-injection":
		return append(base, "mutated response exposed a command-execution signature")
	case "sql-injection":
		return append(base, "mutated response exposed a database-error signature")
	case "ssti-detection", "ssti-advanced":
		return append(base, "mutated response exposed a template-evaluation signature")
	case "ssrf-probe":
		return append(base, "mutated response exposed a server-side request signature")
	default:
		return append(base, "mutated response matched the template signature")
	}
}

func validateOpenRedirect(target, payload string, resp *utils.Response) (bool, string) {
	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" {
		return false, "missing Location header"
	}
	targetURL, err := url.Parse(target)
	if err != nil {
		return false, "invalid target URL"
	}
	redirectURL, err := parseRedirectLocation(resp.FinalURL, location)
	if err != nil || redirectURL.Hostname() == "" {
		return false, "Location is not an absolute external redirect"
	}
	if strings.EqualFold(redirectURL.Hostname(), targetURL.Hostname()) {
		return false, "Location stays on the target host"
	}
	payloadURL, payloadErr := parseRedirectLocation(resp.FinalURL, payload)
	if payloadErr == nil && payloadURL.Hostname() != "" && !strings.EqualFold(redirectURL.Hostname(), payloadURL.Hostname()) {
		return false, "Location host does not match the injected redirect host"
	}
	return true, ""
}

func parseRedirectLocation(baseURL, value string) (*url.URL, error) {
	if strings.HasPrefix(value, "//") {
		value = "http:" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if parsed.IsAbs() {
		return parsed, nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return parsed, nil
	}
	return base.ResolveReference(parsed), nil
}

func hasStrongFileDisclosureSignal(body string) bool {
	signals := []string{
		"root:x:0:0:",
		"daemon:x:",
		"[boot loader]",
		"for 16-bit app support",
		"<?php",
		"-----begin rsa private key-----",
		"-----begin openSSH private key-----",
		"database_password",
		"mysql_password",
		"secret_key",
		"api_key",
	}
	body = strings.ToLower(body)
	for _, signal := range signals {
		if strings.Contains(body, strings.ToLower(signal)) {
			return true
		}
	}
	return false
}

func hasCommandExecutionSignal(body string) bool {
	signals := []string{
		"uid=",
		"gid=",
		"groups=",
		"packets transmitted",
		"bytes received",
		"ttl=",
		"volume serial number",
	}
	body = strings.ToLower(body)
	for _, signal := range signals {
		if strings.Contains(body, signal) {
			return true
		}
	}
	return false
}

func evidencePart(part string) string {
	if strings.EqualFold(part, "header") {
		return "response header"
	}
	return "response body"
}

func isLoginRoute(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	path := strings.ToLower(parsed.Path)
	return strings.Contains(path, "login") || strings.Contains(path, "signin") || strings.Contains(path, "auth")
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

	username, password := parseCredentialPayload(payload)
	value = strings.ReplaceAll(value, "{{username}}", username)
	value = strings.ReplaceAll(value, "{{password}}", password)

	return strings.ReplaceAll(value, "{{payload}}", payload)

}

func parseCredentialPayload(payload string) (string, string) {
	parts := strings.SplitN(payload, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return payload, payload
}

func renderHeaders(headers templates.Headers, baseURL, payload string) map[string]string {
	rendered := make(map[string]string, len(headers))
	for key, value := range headers {
		rendered[key] = renderTemplateValue(value, baseURL, payload)
	}
	return rendered
}

func isInScope(target, requestURL string) bool {
	targetURL, targetErr := url.Parse(target)
	request, requestErr := url.Parse(requestURL)
	if targetErr != nil || requestErr != nil {
		return false
	}
	return strings.EqualFold(targetURL.Hostname(), request.Hostname()) && targetURL.Port() == request.Port()
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
	_ = s.SaveResultsWithOptions(outputFile, true, true, true)
}

func (s *Scanner) SaveResultsWithOptions(outputFile string, saveJSON, saveHTML, savePDF bool) error {

	color.Cyan("Saving report...")

	if saveJSON {
		if err := s.Results.SaveJSON(outputFile); err != nil {
			return fmt.Errorf("save JSON report: %w", err)
		}
	}

	if saveHTML {
		htmlFile := htmlOutputPath(outputFile)
		if err := s.Results.SaveHTML(htmlFile); err != nil {
			return fmt.Errorf("save HTML report: %w", err)
		}
	}

	if savePDF {
		pdfFile := pdfOutputPath(outputFile)
		if err := s.Results.SavePDF(pdfFile); err != nil {
			return fmt.Errorf("save PDF report: %w", err)
		} else {
			color.Green("PDF report saved: %s", pdfFile)
		}
	}
	return nil
}

func pdfOutputPath(outputFile string) string {
	ext := filepath.Ext(outputFile)
	if ext == "" {
		return outputFile + ".pdf"
	}
	return strings.TrimSuffix(outputFile, ext) + ".pdf"
}

func htmlOutputPath(outputFile string) string {

	ext := filepath.Ext(outputFile)

	if ext == "" {
		return outputFile + ".html"
	}

	return strings.TrimSuffix(outputFile, ext) + ".html"

}
