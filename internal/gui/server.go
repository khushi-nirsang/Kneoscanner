// Package gui provides KneoScanner's local, browser-based analyst workspace.
package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/khushi-nirsang/neoscanner/internal/config"
	"github.com/khushi-nirsang/neoscanner/internal/engine"
	scanhistory "github.com/khushi-nirsang/neoscanner/internal/history"
	"github.com/khushi-nirsang/neoscanner/internal/scan"
	"github.com/khushi-nirsang/neoscanner/internal/templates"
)

type scanRequest struct {
	Target             string   `json:"target"`
	Targets            []string `json:"targets"`
	Profile            string   `json:"profile"`
	Severity           string   `json:"severity"`
	Parameters         string   `json:"parameters"`
	Threads            int      `json:"threads"`
	Authorization      bool     `json:"authorization"`
	UserAgent          string   `json:"userAgent"`
	AuthHeader         string   `json:"authHeader"`
	Cookie             string   `json:"cookie"`
	Crawl              bool     `json:"crawl"`
	CrawlMaxDepth      int      `json:"crawlMaxDepth"`
	CrawlMaxPages      int      `json:"crawlMaxPages"`
	Timeout            int      `json:"timeout"`
	Retries            int      `json:"retries"`
	RetryDelay         int      `json:"retryDelay"`
	RequestDelay       int      `json:"requestDelay"`
	MaxRespBytes       int64    `json:"maxRespBytes"`
	FollowRedirects    bool     `json:"followRedirects"`
	VerifySSL          bool     `json:"verifySSL"`
	AllowExternal      bool     `json:"allowExternal"`
	DiscoverOpenAPI    bool     `json:"discoverOpenAPI"`
	DiscoverSitemap    bool     `json:"discoverSitemap"`
	DiscoverScripts    bool     `json:"discoverScripts"`
	ActiveParamTesting bool     `json:"activeParamTesting"`
	ActivePostTesting  bool     `json:"activePostTesting"`
	AIEnabled          bool     `json:"aiEnabled"`
	AIProvider         string   `json:"aiProvider"`
	AIModel            string   `json:"aiModel"`
}
type reportLink struct{ Name, URL string }
type templateSummary struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Risk       string   `json:"risk,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Path       string   `json:"path"`
	Tags       []string `json:"tags,omitempty"`
	CWE        []string `json:"cwe,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	CVSSScore  float64  `json:"cvss_score,omitempty"`
	Valid      bool     `json:"valid"`
	Error      string   `json:"error,omitempty"`
}
type reviewRecord struct {
	FindingID   string    `json:"finding_id"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Status      string    `json:"status"`
	Notes       string    `json:"notes,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type state struct {
	mu                sync.RWMutex
	running           bool
	started, finished time.Time
	err               string
	results           []engine.ScanResult
	aiAnalysis        *engine.AIAnalysis
	reports           []reportLink
	events            []engine.ScanEvent
	cancel            context.CancelFunc
	configFile        string
	historyFile       string
	reviewsFile       string
	subscribers       map[chan engine.ScanEvent]struct{}
}

// Serve starts a loopback-only GUI. It cannot listen on a network interface.
func Serve(address string, openBrowser bool, configFile string) error {
	if address == "" {
		address = "127.0.0.1:8080"
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return fmt.Errorf("GUI address must be a loopback address, such as 127.0.0.1:8080")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	url := "http://" + listener.Addr().String()
	if strings.HasPrefix(url, "http://[::1]") {
		url = "http://localhost" + strings.TrimPrefix(listener.Addr().String(), "[::1]")
	}
	fmt.Printf("KneoScanner GUI: %s\nPress Ctrl+C to stop the GUI.\n", url)
	if openBrowser {
		go open(url)
	}
	historyFile := "reports/history.json"
	reviewsFile := filepath.Join("reports", "reviews.json")
	if cfg, cfgErr := config.LoadConfigFile(configFile); cfgErr == nil && cfg.HistoryFile != "" {
		historyFile = cfg.HistoryFile
		if cfg.OutputDir != "" {
			reviewsFile = filepath.Join(cfg.OutputDir, "reviews.json")
		}
	}
	app := &state{configFile: configFile, historyFile: historyFile, reviewsFile: reviewsFile, subscribers: map[chan engine.ScanEvent]struct{}{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join("web", "index.html"))
	})
	mux.Handle("/web/", http.StripPrefix("/web/", http.FileServer(http.Dir("web"))))
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))
	mux.Handle("/reports/", http.StripPrefix("/reports/", http.FileServer(http.Dir("reports"))))
	mux.HandleFunc("/api/status", app.status)
	mux.HandleFunc("/api/events", app.eventsStream)
	mux.HandleFunc("/api/config", app.configSummary)
	mux.HandleFunc("/api/templates", app.templates)
	mux.HandleFunc("/api/history", app.history)
	mux.HandleFunc("/api/reviews", app.reviews)
	mux.HandleFunc("/api/reviews/update", app.updateReview)
	mux.HandleFunc("/api/scans", app.start)
	mux.HandleFunc("/api/scans/cancel", app.cancelScan)
	return http.Serve(listener, mux)
}

func (s *state) status(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	writeJSON(w, s.snapshotLocked())
}

func (s *state) snapshotLocked() map[string]any {
	return map[string]any{"running": s.running, "started": s.started, "finished": s.finished, "error": s.err, "findings": s.results, "ai_analysis": s.aiAnalysis, "reports": s.reports, "events": s.events}
}

func (s *state) eventsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan engine.ScanEvent, 32)
	s.mu.Lock()
	if s.subscribers == nil {
		s.subscribers = map[chan engine.ScanEvent]struct{}{}
	}
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		s.mu.Unlock()
	}()

	_, _ = fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()
	keepAlive := time.NewTicker(20 * time.Second)
	defer keepAlive.Stop()
	for {
		select {
		case event := <-ch:
			data, _ := json.Marshal(event)
			_, _ = fmt.Fprintf(w, "event: scan\ndata: %s\n\n", data)
			flusher.Flush()
		case <-keepAlive.C:
			_, _ = fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
func (s *state) configSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := config.LoadConfigFile(s.configFile)
	if err != nil {
		http.Error(w, "cannot load config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"templates": cfg.Templates, "output": cfg.Output, "history_file": cfg.HistoryFile, "profile": cfg.ScanProfile,
		"crawl": cfg.Crawl, "crawl_max_depth": cfg.CrawlMaxDepth, "crawl_max_pages": cfg.CrawlMaxPages,
		"discover_openapi": cfg.DiscoverOpenAPI, "discover_sitemap": cfg.DiscoverSitemap, "discover_scripts": cfg.DiscoverScripts,
		"timeout": cfg.Timeout, "retries": cfg.Retries, "retry_delay": cfg.RetryDelay, "request_delay": cfg.RequestDelay,
		"follow_redirects": cfg.FollowRedirects, "verify_ssl": cfg.VerifySSL, "allow_external_urls": cfg.AllowExternalURLs,
		"active_parameter_testing": cfg.ActiveParameterTesting, "active_post_form_testing": cfg.ActivePostFormTesting,
		"redact_sensitive_data": cfg.RedactSensitiveData, "evidence_max_bytes": cfg.EvidenceMaxBytes,
		"ai_enabled": cfg.AIEnabled, "ai_provider": cfg.AIProvider, "ai_model": cfg.AIModel,
	})
}
func (s *state) templates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := config.LoadConfigFile(s.configFile)
	if err != nil {
		http.Error(w, "cannot load config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	items, err := loadTemplateSummaries(cfg.Templates)
	if err != nil {
		http.Error(w, "cannot load templates: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"templates": items})
}
func (s *state) start(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var request scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&request); err != nil {
		http.Error(w, "invalid scan request", http.StatusBadRequest)
		return
	}
	request.Target, request.Profile = strings.TrimSpace(request.Target), strings.ToLower(strings.TrimSpace(request.Profile))
	targets := normalizeTargets(request.Target, request.Targets)
	if len(targets) == 0 {
		http.Error(w, "a target URL is required", http.StatusBadRequest)
		return
	}
	if request.Threads < 1 || request.Threads > 200 {
		http.Error(w, "threads must be between 1 and 200", http.StatusBadRequest)
		return
	}
	if (request.Profile == "active" || request.Profile == "intrusive") && !request.Authorization {
		http.Error(w, "active and intrusive scans require authorization acknowledgement", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		http.Error(w, "a scan is already running", http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.running, s.started, s.finished, s.err, s.results, s.aiAnalysis, s.reports, s.events, s.cancel = true, time.Now(), time.Time{}, "", nil, nil, nil, nil, cancel
	s.mu.Unlock()
	s.addEvent(engine.ScanEvent{Timestamp: time.Now(), Type: "scan.accepted", Message: "Scan queued"})
	go s.run(ctx, request, targets, s.configFile)
	writeJSON(w, map[string]bool{"accepted": true})
}
func (s *state) run(ctx context.Context, request scanRequest, targets []string, configFile string) {
	cfg, err := config.LoadConfigFile(configFile)
	if err == nil {
		cfg.Threads, cfg.ScanProfile, cfg.Severity = request.Threads, request.Profile, strings.TrimSpace(request.Severity)
		if request.UserAgent = strings.TrimSpace(request.UserAgent); request.UserAgent != "" {
			cfg.UserAgent = request.UserAgent
		}
		cfg.Crawl = request.Crawl
		if request.CrawlMaxDepth > 0 {
			cfg.CrawlMaxDepth = request.CrawlMaxDepth
		}
		if request.CrawlMaxPages > 0 {
			cfg.CrawlMaxPages = request.CrawlMaxPages
		}
		if request.Timeout > 0 {
			cfg.Timeout = request.Timeout
		}
		if request.Retries >= 0 {
			cfg.Retries = request.Retries
		}
		if request.RetryDelay > 0 {
			cfg.RetryDelay = request.RetryDelay
		}
		if request.RequestDelay >= 0 {
			cfg.RequestDelay = request.RequestDelay
		}
		if request.MaxRespBytes > 0 {
			cfg.MaxResponseBytes = request.MaxRespBytes
		}
		cfg.FollowRedirects = request.FollowRedirects
		cfg.VerifySSL = request.VerifySSL
		cfg.AllowExternalURLs = request.AllowExternal
		cfg.DiscoverOpenAPI = request.DiscoverOpenAPI
		cfg.DiscoverSitemap = request.DiscoverSitemap
		cfg.DiscoverScripts = request.DiscoverScripts
		cfg.ActiveParameterTesting = request.ActiveParamTesting
		cfg.ActivePostFormTesting = request.ActivePostTesting
		cfg.AIEnabled = request.AIEnabled
		if provider := strings.TrimSpace(request.AIProvider); provider != "" {
			cfg.AIProvider = provider
		}
		if model := strings.TrimSpace(request.AIModel); model != "" {
			cfg.AIModel = model
		}
		if cfg.AuthHeaders == nil {
			cfg.AuthHeaders = map[string]string{}
		}
		if header := strings.TrimSpace(request.AuthHeader); header != "" {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				cfg.AuthHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		if cookie := strings.TrimSpace(request.Cookie); cookie != "" {
			cfg.AuthHeaders["Cookie"] = cookie
		}
		scanner, runErr := scan.RunWithRuntime(ctx, cfg, targets, splitParameters(request.Parameters), request.Authorization, s.addEvent)
		err = runErr
		if scanner != nil {
			s.mu.Lock()
			s.results = append([]engine.ScanResult(nil), scanner.Results.Items...)
			s.aiAnalysis = scanner.Results.AIAnalysis
			s.reports = reportLinks(cfg)
			s.mu.Unlock()
		}
	}
	s.mu.Lock()
	s.running, s.finished, s.cancel = false, time.Now(), nil
	if err != nil {
		s.err = err.Error()
	}
	finished := s.finished
	message := "Scan completed"
	eventType := "scan.completed"
	if err != nil {
		message = err.Error()
		eventType = "scan.failed"
	}
	s.mu.Unlock()
	s.broadcast(engine.ScanEvent{Timestamp: finished, Type: eventType, Message: message})
}

func (s *state) addEvent(event engine.ScanEvent) {
	s.mu.Lock()
	s.events = append(s.events, event)
	if len(s.events) > 100 {
		s.events = s.events[len(s.events)-100:]
	}
	subscribers := make([]chan engine.ScanEvent, 0, len(s.subscribers))
	for ch := range s.subscribers {
		subscribers = append(subscribers, ch)
	}
	s.mu.Unlock()
	for _, ch := range subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}

func (s *state) broadcast(event engine.ScanEvent) {
	s.addEvent(event)
}
func (s *state) cancelScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	cancel, running := s.cancel, s.running
	s.mu.RUnlock()
	if !running || cancel == nil {
		http.Error(w, "no scan is running", http.StatusConflict)
		return
	}
	cancel()
	writeJSON(w, map[string]bool{"cancelled": true})
}
func (s *state) history(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	records, err := scanhistory.Load(s.historyFile)
	if err != nil {
		http.Error(w, "cannot load scan history: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, records)
}
func (s *state) reviews(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	records, err := loadReviews(s.reviewsFile)
	if err != nil {
		http.Error(w, "cannot load reviews: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, records)
}
func (s *state) updateReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var request reviewRecord
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&request); err != nil {
		http.Error(w, "invalid review update", http.StatusBadRequest)
		return
	}
	request.FindingID, request.Fingerprint, request.Status = strings.TrimSpace(request.FindingID), strings.TrimSpace(request.Fingerprint), strings.TrimSpace(request.Status)
	if request.FindingID == "" && request.Fingerprint == "" {
		http.Error(w, "finding_id or fingerprint is required", http.StatusBadRequest)
		return
	}
	if request.Status == "" {
		request.Status = "none"
	}
	request.Notes = strings.TrimSpace(request.Notes)
	if request.Status != "reviewed" && request.Status != "false_positive" && request.Status != "none" {
		http.Error(w, "status must be reviewed, false_positive, or none", http.StatusBadRequest)
		return
	}
	records, err := saveReview(s.reviewsFile, request)
	if err != nil {
		http.Error(w, "cannot save review: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, records)
}
func loadReviews(path string) (map[string]reviewRecord, error) {
	records := map[string]reviewRecord{}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return records, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return records, nil
	}
	return records, json.Unmarshal(data, &records)
}
func saveReview(path string, record reviewRecord) (map[string]reviewRecord, error) {
	records, err := loadReviews(path)
	if err != nil {
		return nil, err
	}
	key := record.FindingID
	if key == "" {
		key = record.Fingerprint
	}
	if record.Status == "none" && strings.TrimSpace(record.Notes) == "" {
		delete(records, key)
	} else {
		record.UpdatedAt = time.Now()
		if record.Status == "none" {
			record.Status = ""
		}
		records[key] = record
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, err
	}
	return records, os.WriteFile(path, data, 0644)
}
func reportLinks(cfg *config.Config) []reportLink {
	base := filepath.Base(cfg.Output)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	links := []reportLink{}
	if cfg.JSONReport {
		links = append(links, reportLink{"JSON report", "/reports/" + base})
	}
	if cfg.HTMLReport {
		links = append(links, reportLink{"HTML report", "/reports/" + stem + ".html"})
	}
	if cfg.PDFReport {
		links = append(links, reportLink{"PDF report", "/reports/" + stem + ".pdf"})
	}
	if cfg.SARIFReport {
		links = append(links, reportLink{"SARIF report", "/reports/" + stem + ".sarif"})
	}
	if filepath.Clean(filepath.Dir(cfg.HistoryFile)) == "reports" {
		links = append(links, reportLink{"Scan history", "/reports/" + filepath.Base(cfg.HistoryFile)})
	}
	return links
}
func loadTemplateSummaries(dir string) ([]templateSummary, error) {
	items := []templateSummary{}
	if _, err := os.Stat(dir); err != nil {
		return items, err
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") && !strings.HasSuffix(strings.ToLower(info.Name()), ".yml") {
			return nil
		}
		relative, _ := filepath.Rel(dir, path)
		item := templateSummary{Path: filepath.ToSlash(relative)}
		tmpl, err := templates.LoadTemplate(path)
		if err != nil {
			item.Valid, item.Error = false, err.Error()
			items = append(items, item)
			return nil
		}
		item.ID, item.Name, item.Severity, item.Risk, item.Confidence = tmpl.ID, tmpl.Info.Name, tmpl.Info.Severity, tmpl.Info.Risk, tmpl.Info.Confidence
		item.Tags, item.CWE, item.CVEs, item.CVSSScore = []string(tmpl.Info.Tags), []string(tmpl.Info.CWE), []string(tmpl.Info.CVEs), tmpl.Info.CVSSScore
		if err := templates.ValidateTemplate(*tmpl); err != nil {
			item.Valid, item.Error = false, err.Error()
		} else {
			item.Valid = true
		}
		items = append(items, item)
		return nil
	})
	return items, err
}
func splitParameters(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Split(value, ",")
}
func normalizeTargets(primary string, extra []string) []string {
	seen := map[string]bool{}
	targets := []string{}
	for _, value := range append([]string{primary}, extra...) {
		for _, part := range strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ';' }) {
			target := strings.TrimSpace(part)
			if target == "" || seen[target] {
				continue
			}
			seen[target] = true
			targets = append(targets, target)
		}
	}
	return targets
}
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func workspacePage() string {
	return decorateWorkspacePage(page)
}
func decorateWorkspacePage(base string) string {
	html := strings.Replace(base, "</head>", `<style>
body.compact main{max-width:1500px}
body.compact .card{padding:14px}
body.compact th,body.compact td{padding:8px 7px}
body.compact .metric{padding:9px}
body.compact .metric b{font-size:19px}
body.compact input,body.compact select{padding:8px}
body.compact pre{max-height:300px}
body.app-shell{background:#07111f;overflow:hidden}
.app-frame{display:grid;grid-template-columns:210px minmax(0,1fr);height:100vh}
.app-sidebar{background:linear-gradient(180deg,#0d2138,#081422);border-right:1px solid var(--line);padding:18px;display:flex;flex-direction:column;gap:16px}
.app-brand{display:flex;gap:11px;align-items:center;padding:7px 4px 14px;border-bottom:1px solid var(--line)}
.app-logo{width:42px;height:42px;border-radius:14px;background:#071321 url('/assets/kneoscanner-logo.png') center/cover no-repeat;box-shadow:0 12px 28px #0007;border:1px solid #2c6f90}
.app-brand h1{font-size:20px;line-height:1}
.app-brand p{font-size:12px;margin:4px 0 0}
.app-nav{display:grid;gap:7px}
.app-nav button{width:100%;text-align:left;background:transparent;color:#b9cce5;border:1px solid transparent;border-radius:11px;padding:11px 12px;font-weight:800}
.app-nav button:hover{background:#102b46;color:var(--text)}
.app-nav button.active{background:linear-gradient(135deg,#143d5d,#12314f);border-color:#2f6389;color:#fff;box-shadow:inset 3px 0 0 var(--accent)}
.app-sidebar-foot{margin-top:auto;color:var(--muted);font-size:12px;line-height:1.5;border-top:1px solid var(--line);padding-top:14px}
.app-main{min-width:0;height:100vh;overflow:auto;background:radial-gradient(circle at 15% 0,#173b61,#07111f 38%)}
.app-main main{max-width:none;margin:0;padding:18px 22px 34px}
.app-topbar{position:sticky;top:0;z-index:20;display:flex;justify-content:space-between;align-items:center;gap:16px;background:rgba(7,17,31,.88);backdrop-filter:blur(14px);border-bottom:1px solid var(--line);padding:14px 22px;margin:-18px -22px 18px}
.app-title h2{font-size:20px}.app-title p{margin:3px 0 0;font-size:12px}
.app-top-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.app-view{display:none}.app-view.active{display:block}
.app-overview-grid{display:grid;grid-template-columns:1.1fr .9fr;gap:16px}
.app-split-view{display:grid;grid-template-columns:minmax(420px,1fr) minmax(520px,.95fr);gap:16px;align-items:start}
body.app-shell .head{display:none}
body.app-shell .grid,body.app-shell .workspace{display:block;margin:0!important}
body.app-shell .workspace>section:first-child,body.app-shell #details{display:block}
body.app-shell #details{position:sticky;top:82px;max-height:calc(100vh - 104px)}
body.app-shell .metrics{grid-template-columns:repeat(6,minmax(110px,1fr))}
@media(max-width:1100px){.app-frame{grid-template-columns:76px minmax(0,1fr)}.app-sidebar{padding:12px 10px}.app-brand div:not(.app-logo),.app-nav span,.app-sidebar-foot{display:none}.app-nav button{text-align:center;padding:12px 6px}.app-split-view,.app-overview-grid{grid-template-columns:1fr}body.app-shell #details{position:static;max-height:none}}
@media(max-width:760px){body.app-shell{overflow:auto}.app-frame{display:block;height:auto}.app-sidebar{position:sticky;top:0;z-index:30;flex-direction:row;overflow:auto}.app-brand{border:0;padding:0}.app-nav{display:flex}.app-main{height:auto;overflow:visible}.app-topbar{position:static;display:block}.app-top-actions{justify-content:flex-start;margin-top:10px}body.app-shell .metrics{grid-template-columns:repeat(2,1fr)}}
.transcript-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:16px 0 7px}
.transcript-head h3{margin:0}
.copy-mini{padding:6px 9px;font-size:12px;border-radius:7px}
.transcript-body{max-height:none;min-height:220px;overflow:auto;resize:vertical}
.transcript-headers{max-height:180px;overflow:auto}
body.compact .transcript-body{max-height:none}
</style></head>`, 1)
	return strings.Replace(html, "</script>", `
(function(){
  const reports=document.getElementById('reports');
  if(!reports||document.getElementById('densityToggle')) return;
  const button=document.createElement('button');
  button.className='secondary';
  button.id='densityToggle';
  button.type='button';
  function applyDensity(enabled){
    document.body.classList.toggle('compact', enabled);
    button.textContent=enabled?'Comfort mode':'Dense mode';
    localStorage.setItem('neoscanner.density', enabled?'compact':'comfort');
  }
  button.onclick=()=>applyDensity(!document.body.classList.contains('compact'));
  reports.parentNode.insertBefore(button,reports);
  applyDensity(localStorage.getItem('neoscanner.density')==='compact');
})();
(function(){
  const actions=document.getElementById('bulkActions');
  if(!actions||document.getElementById('exportVisibleJson')) return;
  function addButton(id,label,handler){
    const button=document.createElement('button');
    button.className='secondary';
    button.id=id;
    button.type='button';
    button.textContent=label;
    button.onclick=handler;
    actions.append(button);
  }
  function visibleItems(){
    return filtered();
  }
  const reviewFilter=document.getElementById('reviewFilter');
  if(reviewFilter&&!document.querySelector('#reviewFilter option[value="has_notes"]')){
    reviewFilter.insertAdjacentHTML('beforeend','<option value="has_notes">Has analyst notes</option><option value="missing_notes">Missing analyst notes</option>');
  }
  function csvCell(value){
    return '"' + String(value??'').replaceAll('"','""') + '"';
  }
  function visibleCSV(items){
    const headers=['severity','confidence','review_status','analyst_notes','name','url','method','parameter','cwe','cves','cvss_score','remediation'];
    const rows=items.map(f=>headers.map(h=>{
      const review=reviews[reviewKey(f)]||{};
      if(h==='review_status') return csvCell(review.status||'unreviewed');
      if(h==='analyst_notes') return csvCell(review.notes||'');
      if(h==='url') return csvCell(f.matched_url);
      if(h==='cwe') return csvCell((f.cwe||[]).join('; '));
      if(h==='cves') return csvCell((f.cves||[]).join('; '));
      return csvCell(f[h]);
    }).join(','));
    return headers.join(',') + '\n' + rows.join('\n');
  }
  function visibleMarkdown(items){
    const counts={critical:0,high:0,medium:0,low:0,info:0};
    items.forEach(f=>counts[f.severity]=(counts[f.severity]||0)+1);
    const lines=['# KneoScanner visible findings summary','','Total visible findings: '+items.length,'','Severity: critical '+(counts.critical||0)+', high '+(counts.high||0)+', medium '+(counts.medium||0)+', low '+(counts.low||0)+', info '+(counts.info||0),''];
    items.slice(0,30).forEach((f,i)=>{
      const status=(reviews[reviewKey(f)]||{}).status||'unreviewed';
      const notes=(reviews[reviewKey(f)]||{}).notes||'';
      lines.push((i+1)+'. ['+(f.severity||'unknown')+'] '+(f.name||'Unnamed finding'));
      lines.push('   - URL: '+(f.matched_url||'not recorded'));
      lines.push('   - Confidence: '+(f.confidence||'not recorded')+'; Review: '+status);
      if(notes) lines.push('   - Analyst notes: '+notes);
      if(f.remediation) lines.push('   - Remediation: '+f.remediation);
    });
    if(items.length>30) lines.push('','_'+(items.length-30)+' additional visible findings omitted from copied summary._');
    return lines.join('\n');
  }
  addButton('exportVisibleJson','Export visible JSON',()=>{const items=visibleItems();if(!items.length){$('status').textContent='No visible findings to export.';return}downloadText('visible-findings.json',JSON.stringify(items,null,2))});
  addButton('exportVisibleCsv','Export visible CSV',()=>{const items=visibleItems();if(!items.length){$('status').textContent='No visible findings to export.';return}downloadText('visible-findings.csv',visibleCSV(items))});
  addButton('copyVisibleSummary','Copy visible summary',()=>{const items=visibleItems();if(!items.length){$('status').textContent='No visible findings to summarize.';return}navigator.clipboard.writeText(visibleMarkdown(items));$('status').textContent='Copied visible findings summary.'});
})();
(function(){
  if(window.__neoScannerPermalinks) return;
  window.__neoScannerPermalinks=true;
  function findingKey(f){return f&&(f.finding_id||f.fingerprint||'')}
  function hashFindingID(){
    const hash=location.hash||'';
    return hash.startsWith('#finding=')?decodeURIComponent(hash.slice(9)):'';
  }
  function setFindingHash(f){
    const id=findingKey(f);
    if(!id) return;
    const next='#finding='+encodeURIComponent(id);
    if(location.hash!==next) history.replaceState(null,'',next);
  }
  function addPermalinkButton(f){
    const bar=document.querySelector('#details .actionbar');
    if(!bar||document.getElementById('copyFindingLink')) return;
    const button=document.createElement('button');
    button.className='secondary';
    button.id='copyFindingLink';
    button.type='button';
    button.textContent='Copy finding link';
    button.onclick=()=>{setFindingHash(f);navigator.clipboard.writeText(location.href);$('status').textContent='Copied finding permalink.'};
    bar.insertBefore(button,bar.firstChild);
  }
  const previousShowDetail=showDetail;
  showDetail=f=>{previousShowDetail(f);if(f){setFindingHash(f);addPermalinkButton(f)}};
  function openHashFinding(){
    const id=hashFindingID();
    if(!id||!state.findings.length) return;
    if(selected&&findingKey(selected)===id) return;
    const match=state.findings.find(f=>findingKey(f)===id);
    if(match){showDetail(match);renderFindings()}
  }
  const previousRender=render;
  render=data=>{previousRender(data);openHashFinding()};
  window.addEventListener('hashchange',openHashFinding);
})();
(function(){
  if(window.__neoScannerIssueTemplate) return;
  window.__neoScannerIssueTemplate=true;
  function issueMarkdown(f){
    const evidence=(f.evidence||[]).map(x=>'- '+x).join('\n')||'- Evidence not recorded';
    const refs=(f.references||[]).map(x=>'- '+x).join('\n')||'- No references recorded';
    const cwe=(f.cwe||[]).join(', ')||'Not mapped';
    const cves=(f.cves||[]).join(', ')||'Not mapped';
    return [
      '# '+(f.name||'KneoScanner finding'),
      '',
      'Severity: '+(f.severity||'unknown'),
      'Confidence: '+(f.confidence||'unknown'),
      'URL: '+(f.matched_url||'not recorded'),
      'Method: '+(f.method||'not recorded'),
      'Parameter: '+(f.parameter||'not applicable'),
      'CWE: '+cwe,
      'CVEs: '+cves,
      '',
      '## Description',
      f.description||'No description recorded.',
      '',
      '## Impact',
      f.impact||'Review impact based on the affected asset and exploitability.',
      '',
      '## Analyst notes',
      (reviews[reviewKey(f)]||{}).notes||'No analyst notes recorded.',
      '',
      '## Evidence',
      evidence,
      '',
      '## Remediation',
      f.remediation||'Validate the finding, patch the affected component, and add a regression test.',
      '',
      '## References',
      refs
    ].join('\n');
  }
  const previousShowDetail=showDetail;
  showDetail=f=>{
    previousShowDetail(f);
    const bar=document.querySelector('#details .actionbar');
    if(!f||!bar||document.getElementById('copyIssueTemplate')) return;
    const button=document.createElement('button');
    button.className='secondary';
    button.id='copyIssueTemplate';
    button.type='button';
    button.textContent='Copy issue template';
    button.onclick=()=>{navigator.clipboard.writeText(issueMarkdown(f));$('status').textContent='Copied issue template.'};
    bar.insertBefore(button,bar.firstChild);
  };
})();
(function(){
  if(window.__neoScannerNotes) return;
  window.__neoScannerNotes=true;
  let notesSaveTimer=null;
  function currentReview(f){return reviews[reviewKey(f)]||{}}
  function hasUnsavedNotes(){return document.getElementById('notesState')&&document.getElementById('notesState').textContent==='Unsaved changes'}
  function reviewUpdatedText(review){return review.updated_at?'Last updated '+new Date(review.updated_at).toLocaleString():'Not saved yet'}
  async function saveFindingNotes(f){
    const existing=currentReview(f);
    const notes=document.getElementById('findingNotes').value;
    const status=existing.status||'none';
    if(document.getElementById('notesState')) document.getElementById('notesState').textContent='Saving…';
    const r=await fetch('/api/reviews/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({finding_id:f.finding_id||'',fingerprint:f.fingerprint||'',status,notes})});
    if(!r.ok){if(document.getElementById('notesState')) document.getElementById('notesState').textContent='Save failed';$('status').textContent='Could not save notes: '+await r.text();return}
    reviews=await r.json();
    reviewMetrics(state.findings);
    renderFindings();
    if(document.getElementById('notesState')) document.getElementById('notesState').textContent='Saved';
    if(document.getElementById('notesUpdated')) document.getElementById('notesUpdated').textContent=reviewUpdatedText(currentReview(f));
    $('status').textContent='Saved finding notes.';
  }
  const previousShowDetail=showDetail;
  showDetail=f=>{
    previousShowDetail(f);
    if(!f||document.getElementById('findingNotes')) return;
    const review=currentReview(f);
    const tabs=document.querySelector('#details .tabs');
    if(!tabs) return;
    tabs.insertAdjacentHTML('beforebegin','<h3 style="margin-top:18px">Analyst notes</h3><textarea id="findingNotes" style="width:100%;min-height:90px;border:1px solid var(--line);border-radius:8px;padding:10px;background:#081727;color:var(--text);font:inherit" placeholder="Add triage notes, owner, validation status, or false-positive reason.">'+esc(review.notes||'')+'</textarea><div class="row" style="margin-top:8px"><button class="secondary" id="saveFindingNotes" type="button">Save notes</button><span class="muted" id="notesState">Saved</span><span class="muted" id="notesUpdated">'+esc(reviewUpdatedText(review))+'</span></div>');
    document.getElementById('findingNotes').oninput=()=>{document.getElementById('notesState').textContent='Unsaved changes';clearTimeout(notesSaveTimer);notesSaveTimer=setTimeout(()=>saveFindingNotes(f),1200)};
    document.getElementById('saveFindingNotes').onclick=()=>saveFindingNotes(f);
    document.getElementById('findingNotes').onkeydown=event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='s'){event.preventDefault();saveFindingNotes(f);document.getElementById('notesState').textContent='Saved'}};
  };
  window.addEventListener('beforeunload',event=>{if(hasUnsavedNotes()){event.preventDefault();event.returnValue=''}});
})();
(function(){
  if(window.__neoScannerEvidenceCopy) return;
  window.__neoScannerEvidenceCopy=true;
  function evidenceBundle(f){
    const parts=['# Evidence bundle: '+(f.name||'KneoScanner finding'),'','Finding ID: '+(f.finding_id||'not recorded'),'Severity: '+(f.severity||'unknown'),'Confidence: '+(f.confidence||'unknown'),'URL: '+(f.matched_url||'not recorded'),'Review: '+((reviews[reviewKey(f)]||{}).status||'unreviewed'),'Analyst notes: '+((reviews[reviewKey(f)]||{}).notes||'none'),''];
    ['request','response','baseline','curl'].forEach(id=>{
      const pane=document.getElementById(id);
      if(!pane) return;
      const text=[...pane.querySelectorAll('pre')].map(x=>x.innerText).join('\n\n')||pane.innerText||'Not captured';
      parts.push('## '+id.charAt(0).toUpperCase()+id.slice(1), text, '');
    });
    return parts.join('\n');
  }
  function addEvidenceCopyButtons(){
    ['request','response','baseline','curl'].forEach(id=>{
      const pane=document.getElementById(id);
      if(!pane||pane.querySelector('.copyEvidencePane')) return;
      const button=document.createElement('button');
      button.className='secondary copyEvidencePane';
      button.type='button';
      button.textContent='Copy pane';
      button.style.margin='0 0 10px';
      button.onclick=()=>{
        const pre=[...pane.querySelectorAll('pre')].map(x=>x.innerText).join('\n\n');
        const text=pre||pane.innerText||'';
        navigator.clipboard.writeText(text);
        $('status').textContent='Copied '+id+' evidence pane.';
      };
      pane.insertBefore(button,pane.firstChild);
    });
  }
  const previousShowDetail=showDetail;
  showDetail=f=>{
    previousShowDetail(f);
    addEvidenceCopyButtons();
    const bar=document.querySelector('#details .actionbar');
    if(!f||!bar||document.getElementById('copyEvidenceBundle')) return;
    const button=document.createElement('button');
    button.className='secondary';
    button.id='copyEvidenceBundle';
    button.type='button';
    button.textContent='Copy evidence bundle';
    button.onclick=()=>{navigator.clipboard.writeText(evidenceBundle(f));$('status').textContent='Copied full evidence bundle.'};
    bar.insertBefore(button,bar.firstChild);
  };
})();
(function(){
  if(window.__neoScannerTriageWorkflow) return;
  window.__neoScannerTriageWorkflow=true;
  function reviewFor(f){return reviews[reviewKey(f)]||{}}
  function ensureTriagePanel(){
    let panel=document.getElementById('triageProgress');
    if(panel) return panel;
    panel=document.createElement('div');
    panel.id='triageProgress';
    panel.className='card';
    panel.style.margin='-2px 0 16px';
    const reviewMetricsPanel=document.getElementById('reviewMetrics');
    reviewMetricsPanel.insertAdjacentElement('afterend',panel);
    return panel;
  }
  function countTriage(){
    const counts={total:state.findings.length,reviewed:0,false_positive:0,unreviewed:0,with_notes:0,missing_notes:0,critical_unreviewed:0,high_unreviewed:0};
    state.findings.forEach(f=>{
      const review=reviewFor(f);
      const status=review.status||'unreviewed';
      const hasNotes=!!(review.notes||'').trim();
      if(status==='reviewed') counts.reviewed++;
      else if(status==='false_positive') counts.false_positive++;
      else counts.unreviewed++;
      if(hasNotes) counts.with_notes++; else counts.missing_notes++;
      if(status==='unreviewed'&&f.severity==='critical') counts.critical_unreviewed++;
      if(status==='unreviewed'&&f.severity==='high') counts.high_unreviewed++;
    });
    return counts;
  }
  function setTriageFilter(review,severity){
    if(review!==undefined) $('reviewFilter').value=review;
    if(severity!==undefined) $('severityFilter').value=severity;
    renderFindings();
  }
  function renderTriageProgress(){
    const panel=ensureTriagePanel();
    const c=countTriage();
    const triaged=c.reviewed+c.false_positive;
    const pct=c.total?Math.round((triaged/c.total)*100):0;
    panel.innerHTML='<div class="toolbar" style="margin:0"><div><h2>Triage progress</h2><span class="count">'+triaged+' / '+c.total+' triaged ('+pct+'%)</span></div><div class="row" style="flex-wrap:wrap"><button class="secondary" id="focusCriticalUnreviewed" type="button">Critical unreviewed: '+c.critical_unreviewed+'</button><button class="secondary" id="focusHighUnreviewed" type="button">High unreviewed: '+c.high_unreviewed+'</button><button class="secondary" id="focusWithNotes" type="button">Has notes: '+c.with_notes+'</button><button class="secondary" id="focusMissingNotes" type="button">Missing notes: '+c.missing_notes+'</button></div></div><div style="height:10px;background:#071321;border:1px solid var(--line);border-radius:99px;overflow:hidden;margin-top:12px"><div style="height:100%;width:'+pct+'%;background:linear-gradient(90deg,var(--accent),var(--blue))"></div></div>';
    document.getElementById('focusCriticalUnreviewed').onclick=()=>setTriageFilter('unreviewed','critical');
    document.getElementById('focusHighUnreviewed').onclick=()=>setTriageFilter('unreviewed','high');
    document.getElementById('focusWithNotes').onclick=()=>setTriageFilter('has_notes',undefined);
    document.getElementById('focusMissingNotes').onclick=()=>setTriageFilter('missing_notes',undefined);
  }
  function annotateNoteBadges(){
    document.querySelectorAll('tr.finding').forEach(row=>{
      if(row.querySelector('.notes-badge')) return;
      const f=state.findings.find(item=>item.finding_id===row.dataset.id);
      if(!f||!(reviewFor(f).notes||'').trim()) return;
      const titleCell=row.children[2];
      if(titleCell) titleCell.insertAdjacentHTML('beforeend','<br><span class="badge info notes-badge">notes</span>');
    });
  }
  const previousRender=render;
  render=data=>{previousRender(data);renderTriageProgress();annotateNoteBadges()};
  const previousRenderFindings=renderFindings;
  renderFindings=()=>{previousRenderFindings();renderTriageProgress();annotateNoteBadges()};
})();
(function(){
  if(window.__neoScannerPolicyAndTemplates) return;
  window.__neoScannerPolicyAndTemplates=true;
  function installPolicyControls(){
    const scanPanel=document.getElementById('scanPanel');
    if(!scanPanel||document.getElementById('advancedPolicy')) return;
    const form=document.getElementById('scan');
    document.getElementById('target').insertAdjacentHTML('afterend','<label>Additional targets</label><textarea id="targetList" style="width:100%;min-height:86px;border:1px solid var(--line);border-radius:8px;padding:10px;background:#081727;color:var(--text);font:inherit" placeholder="One URL per line for multi-target scans"></textarea><p class="muted" id="targetCount">1 target configured</p>');
    function updateTargetCount(){
      const values=[$('target').value,...($('targetList').value||'').split(/[\n,;]/)].map(x=>x.trim()).filter(Boolean);
      document.getElementById('targetCount').textContent=new Set(values).size+' target(s) configured';
    }
    $('target').addEventListener('input',updateTargetCount);
    $('targetList').addEventListener('input',updateTargetCount);
    form.insertAdjacentHTML('beforeend','<div id="advancedPolicy" class="card" style="margin-top:16px;padding:14px"><div class="toolbar" style="margin:0 0 8px"><h3>Advanced scan policy</h3><span class="muted">Auth, crawling, and fingerprinting context</span></div><div class="form-grid"><div><label>User-Agent</label><input id="userAgent" placeholder="KneoScanner/1.0"></div><div><label>Auth header</label><input id="authHeader" placeholder="Authorization: Bearer token"></div><div><label>Cookie header</label><input id="cookieHeader" placeholder="session=...; csrftoken=..."></div><div><label>Crawl enabled</label><label class="check" style="margin:0"><input id="crawlEnabled" type="checkbox" checked><span>Discover links, forms, OpenAPI, sitemap, and script routes</span></label></div><div><label>Crawl max depth</label><input id="crawlMaxDepth" type="number" min="0" max="20" value="3"></div><div><label>Crawl max pages</label><input id="crawlMaxPages" type="number" min="1" max="10000" value="100"></div></div><p class="muted">Sensitive auth values are sent only to scoped targets and redacted from captured evidence.</p></div>');
    document.getElementById('advancedPolicy').insertAdjacentHTML('beforeend','<div id="policyTuning" style="margin-top:14px"><div class="toolbar" style="margin:0 0 8px"><h3>Engine tuning</h3><span class="muted">Timeouts, redirects, TLS, discovery, active checks</span></div><div class="form-grid"><div><label>Timeout seconds</label><input id="timeoutSeconds" type="number" min="1" max="300" value="10"></div><div><label>Retries</label><input id="retries" type="number" min="0" max="10" value="2"></div><div><label>Retry delay ms</label><input id="retryDelay" type="number" min="0" max="10000" value="500"></div><div><label>Request delay ms</label><input id="requestDelay" type="number" min="0" max="60000" value="100"></div><div><label>Max response bytes</label><input id="maxRespBytes" type="number" min="1024" value="2097152"></div><div><label>Scope and transport</label><label class="check" style="margin:0"><input id="followRedirects" type="checkbox" checked><span>Follow redirects</span></label><label class="check" style="margin:6px 0 0"><input id="verifySSL" type="checkbox" checked><span>Verify TLS certificates</span></label><label class="check" style="margin:6px 0 0"><input id="allowExternal" type="checkbox"><span>Allow external template URLs</span></label></div><div><label>Discovery</label><label class="check" style="margin:0"><input id="discoverOpenAPI" type="checkbox" checked><span>OpenAPI / Swagger</span></label><label class="check" style="margin:6px 0 0"><input id="discoverSitemap" type="checkbox" checked><span>Sitemap</span></label><label class="check" style="margin:6px 0 0"><input id="discoverScripts" type="checkbox" checked><span>JavaScript routes</span></label></div><div><label>Active coverage</label><label class="check" style="margin:0"><input id="activeParamTesting" type="checkbox" checked><span>Parameter mutation checks</span></label><label class="check" style="margin:6px 0 0"><input id="activePostTesting" type="checkbox" checked><span>POST form mutation checks</span></label></div></div></div>');
    updateTargetCount();
    try{
      const saved=JSON.parse(localStorage.getItem('neoscanner.scanSettings')||'{}');
      ['targetList','userAgent','authHeader','cookieHeader','crawlMaxDepth','crawlMaxPages','timeoutSeconds','retries','retryDelay','requestDelay','maxRespBytes'].forEach(id=>{if(saved[id]!==undefined&&document.getElementById(id))document.getElementById(id).value=saved[id]});
      ['crawlEnabled','followRedirects','verifySSL','allowExternal','discoverOpenAPI','discoverSitemap','discoverScripts','activeParamTesting','activePostTesting'].forEach(id=>{if(saved[id]!==undefined&&document.getElementById(id))document.getElementById(id).checked=!!saved[id]});
      updateTargetCount();
    }catch(e){}
    ['targetList','userAgent','authHeader','cookieHeader','crawlEnabled','crawlMaxDepth','crawlMaxPages','timeoutSeconds','retries','retryDelay','requestDelay','maxRespBytes','followRedirects','verifySSL','allowExternal','discoverOpenAPI','discoverSitemap','discoverScripts','activeParamTesting','activePostTesting'].forEach(id=>document.getElementById(id).addEventListener('input',()=>{
      let saved={};
      try{saved=JSON.parse(localStorage.getItem('neoscanner.scanSettings')||'{}')}catch(e){}
      saved[id]=document.getElementById(id).type==='checkbox'?document.getElementById(id).checked:document.getElementById(id).value;
      localStorage.setItem('neoscanner.scanSettings',JSON.stringify(saved));
    }));
  }
  async function loadConfigPanel(){
    let panel=document.getElementById('configPanel');
    if(!panel){
      panel=document.createElement('section');
      panel.id='configPanel';
      panel.className='card';
      panel.style.marginTop='16px';
      document.querySelector('.grid').insertAdjacentElement('afterend',panel);
    }
    try{
      const cfg=await (await fetch('/api/config')).json();
      panel.innerHTML='<div class="toolbar" style="margin:0"><div><h2>Runtime configuration</h2><span class="count">Evidence redaction: '+cfg.redact_sensitive_data+' · templates: '+esc(cfg.templates)+'</span></div><button class="secondary" id="refreshConfig" type="button">Refresh config</button></div><div class="facts" style="margin-top:12px"><div class="fact"><span>Output</span>'+esc(cfg.output)+'</div><div class="fact"><span>History</span>'+esc(cfg.history_file)+'</div><div class="fact"><span>Crawl</span>'+esc(cfg.crawl)+' depth '+esc(cfg.crawl_max_depth)+' / pages '+esc(cfg.crawl_max_pages)+'</div><div class="fact"><span>Discovery</span>OpenAPI '+esc(cfg.discover_openapi)+', sitemap '+esc(cfg.discover_sitemap)+', scripts '+esc(cfg.discover_scripts)+'</div><div class="fact"><span>Transport</span>redirects '+esc(cfg.follow_redirects)+', TLS verify '+esc(cfg.verify_ssl)+', external URLs '+esc(cfg.allow_external_urls)+'</div><div class="fact"><span>Timing</span>timeout '+esc(cfg.timeout)+'s, retries '+esc(cfg.retries)+', request delay '+esc(cfg.request_delay)+'ms</div><div class="fact"><span>Active coverage</span>params '+esc(cfg.active_parameter_testing)+', POST forms '+esc(cfg.active_post_form_testing)+'</div><div class="fact"><span>Evidence limit</span>'+esc(cfg.evidence_max_bytes)+' bytes</div><div class="fact"><span>Default profile</span>'+esc(cfg.profile)+'</div></div>';
      document.getElementById('refreshConfig').onclick=loadConfigPanel;
    }catch(e){panel.innerHTML='<h2>Runtime configuration</h2><p class="muted">Could not load config: '+esc(e.message)+'</p>'}
  }
  async function loadTemplatePanel(){
    let panel=document.getElementById('templatePanel');
    if(!panel){
      panel=document.createElement('section');
      panel.id='templatePanel';
      panel.className='card';
      panel.style.marginTop='16px';
      document.getElementById('configPanel').insertAdjacentElement('afterend',panel);
    }
    try{
      const data=await (await fetch('/api/templates')).json();
      const items=data.templates||[];
      const valid=items.filter(t=>t.valid).length, invalid=items.length-valid;
      panel.innerHTML='<div class="toolbar" style="margin:0 0 12px"><div><h2>Template inventory</h2><span class="count">'+items.length+' templates · '+valid+' valid · '+invalid+' invalid</span></div><div class="filters"><input id="templateSearch" placeholder="Search templates, CVE, CWE, severity, tags" style="max-width:360px"><select id="templateSeverity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><select id="templateStatus"><option value="">All status</option><option value="valid">Valid</option><option value="invalid">Invalid</option></select><button class="secondary" id="refreshTemplates" type="button">Refresh templates</button></div></div><div id="templateList"></div>';
      function draw(){
        const q=document.getElementById('templateSearch').value.toLowerCase();
        const sev=document.getElementById('templateSeverity').value;
        const status=document.getElementById('templateStatus').value;
        const filtered=items.filter(t=>[t.id,t.name,t.severity,t.risk,t.confidence,t.path,(t.tags||[]).join(' '),(t.cwe||[]).join(' '),(t.cves||[]).join(' ')].join(' ').toLowerCase().includes(q)&&(!sev||t.severity===sev)&&(!status||(status==='valid'?t.valid:!t.valid)));
        document.getElementById('templateList').innerHTML='<table><tr><th>Status</th><th>Template</th><th>Severity</th><th>Risk</th><th>Mappings</th></tr>'+filtered.slice(0,80).map(t=>'<tr><td><span class="badge '+(t.valid?'info':'critical')+'">'+(t.valid?'valid':'invalid')+'</span></td><td><b>'+esc(t.name||t.id||t.path)+'</b><br><span class="muted">'+esc(t.path)+'</span>'+(t.error?'<br><span class="muted">'+esc(t.error)+'</span>':'')+'</td><td>'+esc(t.severity||'')+'</td><td>'+esc(t.risk||'')+'<br><span class="muted">'+esc(t.confidence||'')+'</span></td><td>'+esc([...(t.cves||[]),...(t.cwe||[])].join(', ')||'not mapped')+'</td></tr>').join('')+'</table>'+(filtered.length>80?'<p class="muted">Showing first 80 matching templates.</p>':'');
      }
      document.getElementById('templateSearch').oninput=draw;
      document.getElementById('templateSeverity').oninput=draw;
      document.getElementById('templateStatus').oninput=draw;
      document.getElementById('refreshTemplates').onclick=loadTemplatePanel;
      draw();
    }catch(e){panel.innerHTML='<h2>Template inventory</h2><p class="muted">Could not load templates: '+esc(e.message)+'</p>'}
  }
  installPolicyControls();
  loadConfigPanel();
  loadTemplatePanel();
})();
(function(){
  if(window.__neoScannerPolicyImportExport) return;
  window.__neoScannerPolicyImportExport=true;
  function policyFieldIDs(){return ['target','targetList','profile','threads','severity','parameters','authorization','userAgent','authHeader','cookieHeader','crawlEnabled','crawlMaxDepth','crawlMaxPages','timeoutSeconds','retries','retryDelay','requestDelay','maxRespBytes','followRedirects','verifySSL','allowExternal','discoverOpenAPI','discoverSitemap','discoverScripts','activeParamTesting','activePostTesting','preset']}
  function collectPolicy(){
    const policy={version:1,exported_at:new Date().toISOString(),fields:{}};
    policyFieldIDs().forEach(id=>{const el=document.getElementById(id);if(el)policy.fields[id]=el.type==='checkbox'?el.checked:el.value});
    return policy;
  }
  function applyPolicy(policy){
    Object.entries((policy&&policy.fields)||{}).forEach(([id,value])=>{const el=document.getElementById(id);if(!el)return;if(el.type==='checkbox')el.checked=!!value;else el.value=value});
    if(document.getElementById('targetList')) document.getElementById('targetList').dispatchEvent(new Event('input'));
    syncAuthorization();
    $('status').textContent='Imported scan policy.';
  }
  function installPolicyImportExport(){
    const advanced=document.getElementById('advancedPolicy');
    if(!advanced||document.getElementById('exportPolicy')) return;
    advanced.insertAdjacentHTML('beforeend','<div class="row" style="margin-top:14px;flex-wrap:wrap"><button class="secondary" id="exportPolicy" type="button">Export policy JSON</button><button class="secondary" id="importPolicyButton" type="button">Import policy JSON</button><input id="importPolicyFile" type="file" accept="application/json,.json" class="hide"></div>');
    document.getElementById('exportPolicy').onclick=()=>downloadText('neoscanner-policy.json',JSON.stringify(collectPolicy(),null,2));
    document.getElementById('importPolicyButton').onclick=()=>document.getElementById('importPolicyFile').click();
    document.getElementById('importPolicyFile').onchange=async event=>{
      const file=event.target.files&&event.target.files[0];
      if(!file)return;
      try{applyPolicy(JSON.parse(await file.text()))}catch(e){$('status').textContent='Could not import policy: '+e.message}
      event.target.value='';
    };
  }
  installPolicyImportExport();
})();
(function(){
  if(window.__neoScannerFindingPagination) return;
  window.__neoScannerFindingPagination=true;
  let findingPage=0;
  let findingPageSize=Number(localStorage.getItem('neoscanner.findingPageSize')||50);
  const baseFiltered=filtered;
  filtered=()=>{
    const all=baseFiltered();
    window.__neoScannerFilteredTotal=all.length;
    if(findingPageSize<=0) return all;
    const maxPage=Math.max(0,Math.ceil(all.length/findingPageSize)-1);
    if(findingPage>maxPage) findingPage=maxPage;
    return all.slice(findingPage*findingPageSize,(findingPage+1)*findingPageSize);
  };
  function installPaginationControls(){
    const actions=document.getElementById('bulkActions');
    if(!actions||document.getElementById('findingPageSize')) return;
    actions.insertAdjacentHTML('beforeend','<span class="muted" id="findingPageStatus">Page 1</span><select id="findingPageSize" style="width:130px"><option value="25">25 rows</option><option value="50">50 rows</option><option value="100">100 rows</option><option value="0">All rows</option></select><button class="secondary" id="prevFindingPage" type="button">Prev page</button><button class="secondary" id="nextFindingPage" type="button">Next page</button>');
    document.getElementById('findingPageSize').value=String(findingPageSize);
    document.getElementById('findingPageSize').oninput=()=>{findingPageSize=Number(document.getElementById('findingPageSize').value);findingPage=0;localStorage.setItem('neoscanner.findingPageSize',findingPageSize);renderFindings()};
    document.getElementById('prevFindingPage').onclick=()=>{findingPage=Math.max(0,findingPage-1);renderFindings()};
    document.getElementById('nextFindingPage').onclick=()=>{findingPage++;renderFindings()};
  }
  function updatePaginationStatus(){
    const total=window.__neoScannerFilteredTotal||0;
    const size=findingPageSize<=0?Math.max(total,1):findingPageSize;
    const pages=findingPageSize<=0?1:Math.max(1,Math.ceil(total/size));
    if(findingPage>=pages) findingPage=pages-1;
    const status=document.getElementById('findingPageStatus');
    if(status) status.textContent=findingPageSize<=0?'Showing all '+total+' matching findings':'Page '+(findingPage+1)+' / '+pages+' · '+total+' matching';
    const prev=document.getElementById('prevFindingPage'), next=document.getElementById('nextFindingPage');
    if(prev) prev.disabled=findingPage<=0||findingPageSize<=0;
    if(next) next.disabled=findingPage>=pages-1||findingPageSize<=0;
  }
  const previousRenderFindings=renderFindings;
  renderFindings=()=>{previousRenderFindings();installPaginationControls();updatePaginationStatus()};
  ['search','severityFilter','confidenceFilter','reviewFilter','sort'].forEach(id=>document.getElementById(id).addEventListener('input',()=>{findingPage=0}));
  installPaginationControls();
})();
(function(){
  if(window.__neoScannerAppShell) return;
  window.__neoScannerAppShell=true;
  const root=document.querySelector('main');
  if(!root) return;
  document.body.classList.add('app-shell');

  const original=[...root.children];
  const head=document.querySelector('.head');
  const metrics=document.getElementById('metrics');
  const reviewMetrics=document.getElementById('reviewMetrics');
  const scanGrid=document.querySelector('.grid');
  const workspace=document.querySelector('.workspace');
  const historyPanel=document.getElementById('historyPanel');
  const historySection=historyPanel?historyPanel.closest('section'):null;
  const reports=document.getElementById('reports');

  const frame=document.createElement('div');
  frame.className='app-frame';
  const sidebar=document.createElement('aside');
  sidebar.className='app-sidebar';
  sidebar.innerHTML='<div class="app-brand"><div class="app-logo" role="img" aria-label="KneoScanner logo"></div><div><h1>KneoScanner</h1><p>Security operations workspace</p></div></div><nav class="app-nav" aria-label="Workspace navigation"><button data-view="overview" class="active" type="button">⌁ <span>Overview</span></button><button data-view="scan" type="button">▶ <span>Scan setup</span></button><button data-view="findings" type="button">◆ <span>Findings</span></button><button data-view="history" type="button">◷ <span>History</span></button><button data-view="templates" type="button">▦ <span>Templates</span></button><button data-view="config" type="button">⚙ <span>Runtime config</span></button></nav><div class="app-sidebar-foot">Loopback-only GUI<br>Evidence is redacted by default.</div>';
  const mainPane=document.createElement('div');
  mainPane.className='app-main';
  const topbar=document.createElement('div');
  topbar.className='app-topbar';
  topbar.innerHTML='<div class="app-title"><h2 id="appViewTitle">Overview</h2><p id="appViewSubtitle" class="muted">Command center for scan status, triage, and reports.</p></div><div class="app-top-actions"></div>';
  const topActions=topbar.querySelector('.app-top-actions');
  if(reports) topActions.appendChild(reports);
  const quickScan=document.createElement('button');
  quickScan.type='button';
  quickScan.className='secondary';
  quickScan.textContent='New scan';
  quickScan.onclick=()=>activateView('scan');
  topActions.prepend(quickScan);

  const views={};
  function makeView(id,title,subtitle){
    const section=document.createElement('section');
    section.className='app-view';
    section.id='view-'+id;
    section.dataset.title=title;
    section.dataset.subtitle=subtitle;
    views[id]=section;
    return section;
  }
  const overview=makeView('overview','Overview','Command center for scan status, triage, and reports.');
  const scan=makeView('scan','Scan setup','Targets, profiles, authorization, and advanced scan policy.');
  const findings=makeView('findings','Findings','Analyst queue with evidence, triage state, notes, and exports.');
  const history=makeView('history','History','Recent scan runs and generated report artifacts.');
  const templates=makeView('templates','Template inventory','Template health, severity, tags, CWE/CVE, and validation state.');
  const config=makeView('config','Runtime config','Current scanner configuration loaded by the GUI.');

  const overviewGrid=document.createElement('div');
  overviewGrid.className='app-overview-grid';
  const left=document.createElement('div');
  const right=document.createElement('div');
  if(metrics) left.appendChild(metrics);
  if(reviewMetrics) left.appendChild(reviewMetrics);
  if(scanGrid&&scanGrid.children[1]) right.appendChild(scanGrid.children[1]);
  overviewGrid.append(left,right);
  overview.appendChild(overviewGrid);
  if(scanGrid&&scanGrid.children[0]) scan.appendChild(scanGrid.children[0]);
  if(workspace){
    const split=document.createElement('div');
    split.className='app-split-view';
    [...workspace.children].forEach(child=>split.appendChild(child));
    findings.appendChild(split);
  }
  if(historySection) history.appendChild(historySection);
  [overview,scan,findings,history,templates,config].forEach(v=>root.appendChild(v));
  original.forEach(node=>{if(node.parentNode===root&&node!==head) node.remove()});
  root.prepend(topbar);
  mainPane.appendChild(root);
  frame.append(sidebar,mainPane);
  document.body.prepend(frame);

  function adoptLatePanels(){
    const templatePanel=document.getElementById('templatePanel');
    if(templatePanel){
      const placeholder=templates.querySelector('[data-shell-placeholder]');
      if(placeholder) placeholder.remove();
      if(templatePanel.parentNode!==templates) templates.appendChild(templatePanel);
    }
    const configPanel=document.getElementById('configPanel');
    if(configPanel){
      const placeholder=config.querySelector('[data-shell-placeholder]');
      if(placeholder) placeholder.remove();
      if(configPanel.parentNode!==config) config.appendChild(configPanel);
    }
    if(!templates.children.length) templates.innerHTML='<section class="card" data-shell-placeholder="true"><h2>Template inventory</h2><p class="muted">Loading template metadata…</p></section>';
    if(!config.children.length) config.innerHTML='<section class="card" data-shell-placeholder="true"><h2>Runtime config</h2><p class="muted">Loading configuration summary…</p></section>';
  }
  function activateView(id){
    adoptLatePanels();
    if(!views[id]) id='overview';
    Object.entries(views).forEach(([key,view])=>view.classList.toggle('active',key===id));
    document.querySelectorAll('.app-nav button').forEach(button=>button.classList.toggle('active',button.dataset.view===id));
    document.getElementById('appViewTitle').textContent=views[id].dataset.title;
    document.getElementById('appViewSubtitle').textContent=views[id].dataset.subtitle;
    localStorage.setItem('neoscanner.appView',id);
  }
  document.querySelectorAll('.app-nav button').forEach(button=>button.onclick=()=>activateView(button.dataset.view));
  const observer=new MutationObserver(adoptLatePanels);
  observer.observe(root,{childList:true,subtree:true});
  setTimeout(()=>activateView(localStorage.getItem('neoscanner.appView')||'overview'),0);
  window.neoScannerActivateView=activateView;
})();
(function(){
  if(window.__kneoScannerTranscriptUpgrade) return;
  window.__kneoScannerTranscriptUpgrade=true;
  transcript=t=>{
    if(!t)return '<p class="muted">No transcript was captured for this check.</p>';
    const headers=Object.keys(t.headers||{}).map(k=>k+': '+(t.headers[k]||[]).join(', ')).join('\n');
    const isResponse=!!t.status_code;
    const body=String(t.body||'').replace(/^\s+/, '');
    const facts=[
      ['Method',t.method||'not recorded'],
      ['URL',t.url||'not recorded'],
      ['Final URL',t.final_url||'same as requested']
    ];
    if(isResponse){
      facts.push(['Status',t.status_code],['Duration',(t.duration_ms??'not recorded')+' ms'],['Captured body',(t.body_size??'not recorded')+' bytes'+(t.truncated?' (truncated)':'')]);
    }else{
      facts.push(['Request body',(t.body_size??0)+' bytes']);
    }
    return '<div class="facts">'+facts.map(([label,value])=>'<div class="fact"><span>'+esc(label)+'</span>'+esc(value)+'</div>').join('')+'</div><div class="transcript-head"><h3>Headers'+(t.redacted?' (sensitive values redacted)':'')+'</h3><button class="secondary copy-mini transcript-copy" data-copy-target="headers" type="button">Copy headers</button></div><pre class="transcript-headers" data-transcript-part="headers">'+esc(headers||'No headers captured')+'</pre><div class="transcript-head"><h3>'+(isResponse?'Response body':'Request body')+'</h3><button class="secondary copy-mini transcript-copy" data-copy-target="body" type="button">Copy body</button></div><pre class="transcript-body" data-transcript-part="body">'+esc(body||'No body captured')+'</pre>';
  };
  document.addEventListener('click',event=>{
    const button=event.target&&event.target.closest&&event.target.closest('.transcript-copy');
    if(!button) return;
    const block=button.parentElement&&button.parentElement.nextElementSibling;
    if(!block) return;
    navigator.clipboard.writeText(block.textContent||'');
    const label=button.textContent;
    button.textContent='Copied';
    setTimeout(()=>button.textContent=label,1200);
  });
})();
(function(){
  if(window.__kneoScannerTabMemory) return;
  window.__kneoScannerTabMemory=true;
  let activePane='request';
  document.addEventListener('click',event=>{
    const tab=event.target&&event.target.closest&&event.target.closest('.tab[data-pane]');
    if(tab) activePane=tab.dataset.pane||'request';
  },true);
  const previousShowDetail=showDetail;
  showDetail=(finding, options={})=>{
    const before=document.querySelector('.tab.active[data-pane]');
    if(before) activePane=before.dataset.pane||activePane;
    previousShowDetail(finding, options);
    const wanted=activePane||'request';
    const tab=document.querySelector('.tab[data-pane="'+wanted+'"]');
    const pane=document.getElementById(wanted);
    if(tab&&pane){
      document.querySelectorAll('.tab,.pane').forEach(x=>x.classList.remove('active'));
      tab.classList.add('active');
      pane.classList.add('active');
    }
  };
})();
(function(){
  if(window.__kneoScannerScrollGuard) return;
  window.__kneoScannerScrollGuard=true;
  const previousShowDetail=showDetail;
  showDetail=(finding, options={})=>{
    const pane=document.querySelector('.app-main');
    const top=pane?pane.scrollTop:window.scrollY;
    const details=document.getElementById('details');
    const detailTop=details?details.scrollTop:0;
    const activePane=document.querySelector('.pane.active');
    const activePaneID=activePane?activePane.id:'';
    const partScroll={};
    document.querySelectorAll('.pane.active pre[data-transcript-part]').forEach(pre=>partScroll[pre.dataset.transcriptPart]=pre.scrollTop);
    const suppress=window.__kneoSuppressDetailScroll||options.scroll===false;
    const originalScrollIntoView=Element.prototype.scrollIntoView;
    if(suppress){
      Element.prototype.scrollIntoView=function(){};
    }
    try{
      previousShowDetail(finding);
    }finally{
      if(suppress) Element.prototype.scrollIntoView=originalScrollIntoView;
    }
    if(suppress){
      const restore=()=>{
        if(pane){pane.scrollTop=top}else{window.scrollTo(0,top)}
        const freshDetails=document.getElementById('details');
        if(freshDetails) freshDetails.scrollTop=detailTop;
        if(activePaneID){
          document.querySelectorAll('#'+activePaneID+' pre[data-transcript-part]').forEach(pre=>{
            if(partScroll[pre.dataset.transcriptPart]!==undefined) pre.scrollTop=partScroll[pre.dataset.transcriptPart];
          });
        }
      };
      requestAnimationFrame(restore);
      setTimeout(restore,80);
    }
  };
  const previousRender=render;
  render=data=>{
    window.__kneoSuppressDetailScroll=true;
    try{previousRender(data)}finally{window.__kneoSuppressDetailScroll=false}
  };
})();
</script>`, 1)
}
func open(url string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		command = exec.Command("open", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	_ = command.Start()
}

const page = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KneoScanner Workspace</title><style>
:root{color-scheme:dark;--bg:#07111f;--panel:#102138;--panel2:#0b1a2c;--line:#284563;--text:#e9f2ff;--muted:#9bb0c8;--accent:#4dd5a3;--blue:#72a8ff;--danger:#ff7b83;--warn:#f6b85c}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 5% 0,#153965,#07111f 42%);font:14px Inter,Segoe UI,sans-serif;color:var(--text)}main{max-width:1320px;margin:auto;padding:32px 22px}h1,h2,h3{margin:0}h1{font-size:32px}h2{font-size:18px}h3{font-size:14px}p{color:var(--muted);line-height:1.55}.head,.toolbar,.row,.detail-head{display:flex;align-items:center;gap:12px}.head{justify-content:space-between;margin-bottom:22px}.grid{display:grid;grid-template-columns:1.15fr .85fr;gap:16px}.workspace{display:grid;grid-template-columns:minmax(0,1fr) 430px;gap:16px;align-items:start}.card{background:rgba(16,33,56,.95);border:1px solid var(--line);border-radius:14px;padding:20px;box-shadow:0 16px 40px #0004}.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:16px 0}.metric{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:13px}.metric b{font-size:24px;display:block;margin-bottom:4px}.muted{color:var(--muted)}label{display:block;font-weight:650;margin:13px 0 6px}input,select{width:100%;border:1px solid var(--line);border-radius:8px;padding:10px;background:#081727;color:var(--text);font:inherit}.form-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.check{display:flex;gap:9px;align-items:flex-start;margin-top:16px;color:var(--muted)}.check input{width:auto;margin-top:3px}button,.button{border:0;border-radius:8px;padding:10px 14px;background:var(--accent);color:#03231a;font-weight:800;cursor:pointer;text-decoration:none;display:inline-block}.button.secondary,button.secondary{background:transparent;color:var(--blue);border:1px solid var(--line)}button:disabled{opacity:.55;cursor:wait}.warning{border-left:3px solid var(--warn);padding-left:12px;color:#ead09d}.status{min-height:48px;color:var(--muted)}.toolbar{justify-content:space-between;flex-wrap:wrap;margin:18px 0}.filters{display:flex;gap:8px;flex-wrap:wrap}.filters input{width:260px}.filters select{width:150px}.count{color:var(--muted)}.chips{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 14px}.chip{background:#102c49;border:1px solid var(--line);border-radius:99px;color:#cfe4ff;padding:6px 9px}.chip button{background:transparent;border:0;color:#9bc4ff;padding:0 0 0 6px}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:12px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;word-break:break-word}th{color:#a8c8ea;font-size:11px;text-transform:uppercase;letter-spacing:.04em}tr.finding{cursor:pointer}tr.finding:hover{background:#193451}tr.finding.selected-row{background:#173e5d;outline:1px solid var(--accent);outline-offset:-1px}.badge{display:inline-block;padding:3px 8px;border-radius:99px;font-size:11px;font-weight:800;text-transform:uppercase}.critical{background:#6c1d37;color:#ffdbe3}.high{background:#713137;color:#ffd8d8}.medium{background:#6e5423;color:#ffe5a6}.low{background:#274f61;color:#c5efff}.info{background:#293b68;color:#dbe6ff}.confidence{color:var(--muted);font-size:12px}.link{color:#9bc4ff;text-decoration:none}.link:hover{text-decoration:underline}.empty{padding:34px;text-align:center;color:var(--muted)}#details{position:sticky;top:16px;max-height:calc(100vh - 32px);overflow:auto}.detail{display:block}.detail:not(.visible){min-height:260px}.detail-head{justify-content:space-between}.tabs{display:flex;gap:6px;border-bottom:1px solid var(--line);margin:18px 0 12px}.tab{background:transparent;color:var(--muted);border:0;border-bottom:2px solid transparent;border-radius:0;padding:9px 4px;margin:0}.tab.active{color:var(--text);border-color:var(--accent)}.pane{display:none}.pane.active{display:block}.facts{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.fact{background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:10px}.fact span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;margin-bottom:4px}pre{white-space:pre-wrap;word-break:break-word;margin:0;background:#071321;border:1px solid var(--line);border-radius:8px;padding:12px;max-height:420px;overflow:auto;color:#d9e8f9}.evidence{margin:8px 0;padding-left:18px}.report-links{display:flex;gap:8px;flex-wrap:wrap}.hide{display:none}@media(max-width:1100px){.workspace{grid-template-columns:1fr}#details{position:static;max-height:none}}@media(max-width:900px){.grid,.form-grid,.facts{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(3,1fr)}.head{align-items:flex-start;flex-direction:column}.filters input{width:100%}main{padding:22px 13px}}@media(max-width:500px){.metrics{grid-template-columns:repeat(2,1fr)}}
</style></head><body><main><div class="head"><div><h1>KneoScanner</h1><p>Evidence-first local vulnerability scanning workspace.</p></div><div id="reports" class="report-links"></div></div><div class="metrics" id="metrics"><div class="metric"><b>0</b><span class="muted">Findings</span></div></div><div id="reviewMetrics" class="metrics" style="margin-top:-6px"></div><div class="grid"><section class="card"><div class="toolbar"><h2>New scan</h2><button class="secondary collapse" data-target="scanPanel" type="button">Collapse</button></div><div id="scanPanel"><div class="row" style="margin:14px 0;align-items:end"><div style="flex:1"><label>Scan preset</label><select id="preset"><option value="">Custom settings</option><option value="passive_recon">Passive recon</option><option value="safe_web">Safe web app scan</option><option value="active_params">Active parameter testing</option><option value="intrusive_lab">Intrusive lab validation</option></select></div><button class="secondary" id="applyPreset" type="button">Apply preset</button></div><form id="scan"><label>Target URL</label><input id="target" placeholder="https://staging.example.com" required><div class="form-grid"><div><label>Profile</label><select id="profile"><option value="passive">Passive</option><option value="safe" selected>Safe</option><option value="active">Active</option><option value="intrusive">Intrusive</option></select></div><div><label>Threads</label><input id="threads" type="number" min="1" max="200" value="25"></div><div><label>Minimum severity</label><select id="severity"><option value="">All findings</option><option value="info">Info</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></div><div><label>Active parameters</label><input id="parameters" placeholder="id, search"></div></div><label class="check"><input id="authorization" type="checkbox"><span>I confirm I am authorized to scan this target. Required for Active and Intrusive profiles.</span></label><button id="submit">Start scan</button></form></div></section><aside class="card"><h2>Scan status</h2><p id="status" class="status">Ready. Evidence is captured with credential redaction enabled.</p><p class="warning">Active and intrusive modes can mutate requests. Review evidence before treating a finding as confirmed.</p><p class="muted">Use the detail panel to inspect sanitized HTTP evidence, compare baseline requests, copy a reproduction command, and open remediation references.</p><p class="muted">Shortcuts: <b>/</b> search, <b>n</b>/<b>p</b> next/previous finding, <b>r</b> reviewed, <b>f</b> false positive, <b>Esc</b> close detail.</p></aside></div><div class="workspace" style="margin-top:16px"><section class="card"><div class="toolbar"><div><h2>Findings</h2><span id="count" class="count">0 findings</span></div><div class="filters"><input id="search" placeholder="Search name, URL, CWE, evidence"><select id="severityFilter"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select><select id="confidenceFilter"><option value="">All confidence</option><option>confirmed</option><option>firm</option><option>potential</option></select><select id="reviewFilter"><option value="">All review states</option><option value="unreviewed">Unreviewed only</option><option value="reviewed">Reviewed</option><option value="false_positive">False positives</option></select><select id="sort"><option value="severity">Sort: severity</option><option value="name">Sort: name</option><option value="url">Sort: URL</option></select></div></div><div id="filterChips" class="chips"></div><div class="row" id="bulkActions" style="margin:0 0 14px;flex-wrap:wrap"><span class="muted" id="selectedCount">0 selected</span><button class="secondary" id="selectVisible" type="button">Select visible</button><button class="secondary" id="clearSelection" type="button">Clear selection</button><button class="secondary" id="bulkReviewed" type="button">Mark selected reviewed</button><button class="secondary" id="bulkFalsePositive" type="button">Mark selected false positive</button><button class="secondary" id="bulkClearReview" type="button">Clear selected review</button><button class="secondary" id="exportSelected" type="button">Export selected JSON</button></div><div id="findings" class="empty">Run a scan to populate the analyst queue.</div></section><section id="details" class="card detail"><div class="empty">Select a finding to inspect evidence, remediation, and sanitized HTTP transcripts.</div></section></div><section class="card" style="margin-top:16px"><div class="toolbar"><div><h2>Scan history</h2><span class="count" id="historyCount">No previous scans loaded</span></div><div class="row"><button id="refreshHistory" class="secondary" type="button">Refresh history</button><button class="secondary collapse" data-target="historyPanel" type="button">Collapse</button></div></div><div id="historyPanel"><div id="history" class="empty">Scan history will appear here after reports are generated.</div></div></section></main><script>
const $=id=>document.getElementById(id);let state={findings:[],reports:[]},selected=null,selectedFindings=new Set();const rank={critical:5,high:4,medium:3,low:2,info:1};
function esc(v){const d=document.createElement('div');d.textContent=v??'';return d.innerHTML}function url(v){return /^https?:\/\//i.test(v||'')?v:''}function link(v){const u=url(v);return u?'<a class="link" href="'+esc(u)+'" target="_blank" rel="noreferrer">'+esc(v)+'</a>':esc(v)}function nice(v){return esc(v||'not recorded')}
function metrics(items){const counts={critical:0,high:0,medium:0,low:0,info:0};items.forEach(x=>counts[x.severity]=(counts[x.severity]||0)+1);$('metrics').innerHTML=['Findings|'+items.length,'Critical|'+counts.critical,'High|'+counts.high,'Medium|'+counts.medium,'Low|'+counts.low,'Info|'+counts.info].map(x=>{const p=x.split('|');return '<div class="metric"><b>'+p[1]+'</b><span class="muted">'+p[0]+'</span></div>'}).join('')}
function reviewMetrics(items){const counts={unreviewed:0,reviewed:0,false_positive:0};items.forEach(f=>{const status=(reviews[reviewKey(f)]||{}).status||'unreviewed';counts[status]=(counts[status]||0)+1});$('reviewMetrics').innerHTML=[['unreviewed','Unreviewed',counts.unreviewed],['reviewed','Reviewed',counts.reviewed],['false_positive','False positives',counts.false_positive]].map(x=>'<div class="metric review-metric" data-review="'+x[0]+'"><b>'+x[2]+'</b><span class="muted">'+x[1]+'</span></div>').join('');document.querySelectorAll('.review-metric').forEach(card=>{card.style.cursor='pointer';card.title='Filter by '+card.dataset.review;card.onclick=()=>{$('reviewFilter').value=card.dataset.review;renderFindings()}})}
function filtered(){const q=$('search').value.toLowerCase(),sev=$('severityFilter').value,con=$('confidenceFilter').value,review=$('reviewFilter').value,sort=$('sort').value;let list=state.findings.filter(f=>{const text=[f.name,f.matched_url,f.parameter,(f.cwe||[]).join(' '),(f.evidence||[]).join(' '),(reviews[reviewKey(f)]||{}).notes||''].join(' ').toLowerCase();const reviewRecord=reviews[reviewKey(f)]||{};const status=reviewRecord.status||'unreviewed';const hasNotes=!!(reviewRecord.notes||'').trim();const reviewMatch=!review||status===review||(review==='has_notes'&&hasNotes)||(review==='missing_notes'&&!hasNotes);return (!q||text.includes(q))&&(!sev||f.severity===sev)&&(!con||f.confidence===con)&&reviewMatch});return list.sort((a,b)=>sort==='name'?a.name.localeCompare(b.name):sort==='url'?a.matched_url.localeCompare(b.matched_url):(rank[b.severity]||0)-(rank[a.severity]||0)||a.name.localeCompare(b.name))}
function updateSelectedCount(){$('selectedCount').textContent=selectedFindings.size+' selected'}
function renderFilterChips(){const chips=[];if($('search').value)chips.push(['search','Search: '+$('search').value]);if($('severityFilter').value)chips.push(['severityFilter','Severity: '+$('severityFilter').value]);if($('confidenceFilter').value)chips.push(['confidenceFilter','Confidence: '+$('confidenceFilter').value]);if($('reviewFilter').value)chips.push(['reviewFilter','Review: '+$('reviewFilter').options[$('reviewFilter').selectedIndex].text]);$('filterChips').innerHTML=chips.map(c=>'<span class="chip">'+esc(c[1])+' <button type="button" data-filter="'+esc(c[0])+'" title="Clear this filter">×</button></span>').join('');document.querySelectorAll('#filterChips button').forEach(b=>b.onclick=()=>{$(b.dataset.filter).value='';renderFindings()})}
function renderFindings(){renderFilterChips();const list=filtered();$('count').textContent=list.length+' of '+state.findings.length+' findings';if(!list.length){$('findings').innerHTML='<div class="empty">No findings match these filters.</div>';updateSelectedCount();return}$('findings').innerHTML='<table><tr><th><input id="toggleVisible" type="checkbox" title="Select visible findings"></th><th>Severity</th><th>Finding</th><th>Location</th><th>Confidence</th><th>Proof</th></tr>'+list.map(f=>{const key=reviewKey(f),current=selected&&selected.finding_id===f.finding_id;return '<tr class="finding '+(current?'selected-row':'')+'" data-id="'+esc(f.finding_id)+'"><td><input class="selectFinding" type="checkbox" data-key="'+esc(key)+'" '+(selectedFindings.has(key)?'checked':'')+'></td><td><span class="badge '+esc(f.severity)+'">'+esc(f.severity)+'</span></td><td><b>'+esc(f.name)+'</b><br><span class="muted">'+esc(f.template_id)+'</span></td><td>'+link(f.matched_url)+'<br><span class="muted">'+esc(f.method)+' '+esc(f.parameter||'')+'</span></td><td class="confidence">'+esc(f.confidence)+'<br>'+reviewBadge(f)+'</td><td>'+esc((f.evidence||[])[0]||'Evidence captured')+'</td></tr>'}).join('')+'</table>';document.querySelectorAll('tr.finding').forEach(row=>row.onclick=event=>{if(event.target&&event.target.classList.contains('selectFinding'))return;showDetail(state.findings.find(f=>f.finding_id===row.dataset.id))});document.querySelectorAll('.selectFinding').forEach(box=>box.onchange=()=>{box.checked?selectedFindings.add(box.dataset.key):selectedFindings.delete(box.dataset.key);updateSelectedCount()});$('toggleVisible').onchange=event=>{list.forEach(f=>event.target.checked?selectedFindings.add(reviewKey(f)):selectedFindings.delete(reviewKey(f)));renderFindings()};updateSelectedCount()}
function transcript(t){if(!t)return '<p class="muted">No transcript was captured for this check.</p>';const headers=Object.keys(t.headers||{}).map(k=>k+': '+(t.headers[k]||[]).join(', ')).join('\n');return '<div class="facts"><div class="fact"><span>Status</span>'+nice(t.status_code)+'</div><div class="fact"><span>Duration</span>'+nice(t.duration_ms)+' ms</div><div class="fact"><span>Captured body</span>'+nice(t.body_size)+' bytes'+(t.truncated?' (truncated)':'')+'</div></div><h3 style="margin:16px 0 7px">Headers'+(t.redacted?' (sensitive values redacted)':'')+'</h3><pre>'+esc(headers||'No headers captured')+'</pre><h3 style="margin:16px 0 7px">Body</h3><pre>'+esc(t.body||'No body captured')+'</pre>'}
function curl(f){const r=f.request||{},h=r.headers||{};let out='curl -i -X '+(r.method||f.method||'GET')+' '+JSON.stringify(r.url||f.matched_url||'');Object.keys(h).forEach(k=>out+=' -H '+JSON.stringify(k+': '+h[k].join(', ')));if(r.body)out+=' --data-raw '+JSON.stringify(r.body);return out}
function showDetail(f){if(!f)return;selected=f;const refs=(f.references||[]).map(x=>link(x)).join('<br>')||'No references recorded';const cves=(f.cves||[]).map(esc).join(', ')||'Not applicable / no product-version mapping';$('details').classList.add('visible');$('details').innerHTML='<div class="detail-head"><div><span class="badge '+esc(f.severity)+'">'+esc(f.severity)+'</span> <span class="confidence">'+esc(f.confidence)+'</span><h2 style="margin-top:8px">'+esc(f.name)+'</h2><p>'+esc(f.description)+'</p></div><button class="secondary" id="close">Close</button></div><div class="facts"><div class="fact"><span>Finding ID</span>'+esc(f.finding_id)+'</div><div class="fact"><span>CWE</span>'+esc((f.cwe||[]).join(', ')||'Not mapped')+'</div><div class="fact"><span>CVSS</span>'+esc(f.cvss_score||'Not scored')+' '+esc(f.cvss_vector||'')+'</div><div class="fact"><span>Parameter</span>'+esc(f.parameter||'Not applicable')+'</div><div class="fact"><span>Impact</span>'+esc(f.impact||'Review remediation')+'</div><div class="fact"><span>CVEs</span>'+cves+'</div></div><h3 style="margin-top:18px">Verification evidence</h3><ul class="evidence">'+(f.evidence||[]).map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul><h3>Remediation</h3><p>'+esc(f.remediation||'Validate the finding, patch the affected component, and add a regression test.')+'</p><h3>References</h3><p>'+refs+'</p><div class="tabs"><button class="tab active" data-pane="request">Request</button><button class="tab" data-pane="response">Response</button><button class="tab" data-pane="baseline">Baseline</button><button class="tab" data-pane="curl">cURL</button></div><div id="request" class="pane active">'+transcript(f.request)+'</div><div id="response" class="pane">'+transcript(f.response)+'</div><div id="baseline" class="pane">'+transcript(f.baseline)+'</div><div id="curl" class="pane"><p class="muted">This is a sanitized reproduction command. Replace redacted secrets only in an authorized environment.</p><pre id="curltext">'+esc(curl(f))+'</pre><button class="secondary" id="copy">Copy cURL</button></div>';$('close').onclick=()=>$('details').classList.remove('visible');document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab,.pane').forEach(x=>x.classList.remove('active'));b.classList.add('active');$(b.dataset.pane).classList.add('active')});$('copy').onclick=()=>navigator.clipboard.writeText(curl(f));$('details').scrollIntoView({behavior:'smooth',block:'start'})}
function detailEditing(){return document.activeElement&&document.activeElement.id==='findingNotes'}
function render(data){state.findings=data.findings||[];state.reports=data.reports||[];metrics(state.findings);reviewMetrics(state.findings);$('reports').innerHTML=state.reports.map(r=>'<a class="button secondary" href="'+esc(r.URL)+'" target="_blank">'+esc(r.Name)+'</a>').join('');const started=data.started?new Date(data.started):null;if(data.running){$('status').textContent='Scanning since '+started.toLocaleTimeString()+' — findings will appear when the scan completes.';$('submit').disabled=true}else{$('submit').disabled=false;$('status').textContent=data.error?'Scan failed: '+data.error:data.finished?'Scan completed at '+new Date(data.finished).toLocaleTimeString()+' with '+state.findings.length+' findings.':'Ready. Evidence is captured with credential redaction enabled.'}renderFindings();if(selected&&!detailEditing()){showDetail(state.findings.find(f=>f.finding_id===selected.finding_id)||selected)}}
async function poll(){try{render(await (await fetch('/api/status')).json())}catch(e){$('status').textContent='Connection error: '+e.message}}setInterval(poll,1200);poll();['search','severityFilter','confidenceFilter','reviewFilter','sort'].forEach(id=>$(id).addEventListener('input',renderFindings));$('scan').addEventListener('submit',async e=>{e.preventDefault();saveScanSettings();$('submit').disabled=true;const body={target:$('target').value,targets:$('targetList')?$('targetList').value.split(/[\n,;]/).map(x=>x.trim()).filter(Boolean):[],profile:$('profile').value,threads:+$('threads').value,severity:$('severity').value,parameters:$('parameters').value,authorization:$('authorization').checked,userAgent:$('userAgent')?$('userAgent').value:'',authHeader:$('authHeader')?$('authHeader').value:'',cookie:$('cookieHeader')?$('cookieHeader').value:'',crawl:$('crawlEnabled')?$('crawlEnabled').checked:true,crawlMaxDepth:$('crawlMaxDepth')?+$('crawlMaxDepth').value:0,crawlMaxPages:$('crawlMaxPages')?+$('crawlMaxPages').value:0,timeout:$('timeoutSeconds')?+$('timeoutSeconds').value:0,retries:$('retries')?+$('retries').value:0,retryDelay:$('retryDelay')?+$('retryDelay').value:0,requestDelay:$('requestDelay')?+$('requestDelay').value:0,maxRespBytes:$('maxRespBytes')?+$('maxRespBytes').value:0,followRedirects:$('followRedirects')?$('followRedirects').checked:true,verifySSL:$('verifySSL')?$('verifySSL').checked:true,allowExternal:$('allowExternal')?$('allowExternal').checked:false,discoverOpenAPI:$('discoverOpenAPI')?$('discoverOpenAPI').checked:true,discoverSitemap:$('discoverSitemap')?$('discoverSitemap').checked:true,discoverScripts:$('discoverScripts')?$('discoverScripts').checked:true,activeParamTesting:$('activeParamTesting')?$('activeParamTesting').checked:true,activePostTesting:$('activePostTesting')?$('activePostTesting').checked:true};const r=await fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok){$('status').textContent='Cannot start scan: '+await r.text();$('submit').disabled=false}else{$('status').textContent='Scan queued…'}});
const runtimeControls=document.createElement('div');runtimeControls.innerHTML='<button id="cancel" class="secondary hide" type="button">Cancel scan</button><div id="activity" class="muted" style="margin-top:12px;max-height:110px;overflow:auto"></div>';$('status').after(runtimeControls);$('cancel').onclick=async()=>{const r=await fetch('/api/scans/cancel',{method:'POST'});if(!r.ok)$('status').textContent='Cancel failed: '+await r.text()};const originalRender=render;render=data=>{originalRender(data);const events=data.events||[];const cancel=$('cancel');cancel.classList.toggle('hide',!data.running);$('activity').innerHTML=events.slice(-6).reverse().map(e=>'<div>'+esc(new Date(e.timestamp).toLocaleTimeString())+' · '+esc(e.message)+'</div>').join('')};
const resetFilters=document.createElement('button');resetFilters.className='secondary';resetFilters.type='button';resetFilters.textContent='Reset filters';document.querySelector('.filters').append(resetFilters);resetFilters.onclick=()=>{$('search').value='';$('severityFilter').value='';$('confidenceFilter').value='';$('reviewFilter').value='';$('sort').value='severity';renderFindings()};const priorDetail=showDetail;showDetail=f=>{priorDetail(f);if(f&&f.technologies&&f.technologies.length){const facts=$('details').querySelector('.facts');facts.insertAdjacentHTML('beforeend','<div class="fact"><span>Technologies</span>'+esc(f.technologies.join(', '))+'</div>')}};const priorRender=render;render=data=>{priorRender(data);if(data.running&&data.started){const elapsed=Math.max(0,Math.floor((Date.now()-new Date(data.started))/1000));const events=data.events||[];$('status').textContent='Scanning for '+Math.floor(elapsed/60)+'m '+(elapsed%60)+'s. '+(events.length?events[events.length-1].message:'Preparing scan…')}};
const priorMetrics=metrics;metrics=items=>{priorMetrics(items);const levels=['','critical','high','medium','low','info'];document.querySelectorAll('.metric').forEach((card,index)=>{if(!levels[index])return;card.style.cursor='pointer';card.title='Filter findings by '+levels[index];card.onclick=()=>{$('severityFilter').value=levels[index];renderFindings()}})};document.addEventListener('keydown',event=>{if(event.key==='Escape'){$('details').classList.remove('visible')}});document.addEventListener('click',event=>{if(event.target&&event.target.id==='copy'){setTimeout(()=>{event.target.textContent='Copied';setTimeout(()=>{event.target.textContent='Copy cURL'},1400)},0)}});
const authBox=$('authorization'),profileBox=$('profile');function syncAuthorization(){const required=['active','intrusive'].includes(profileBox.value);const label=authBox.closest('label');label.style.color=required&&!authBox.checked?'#ffd27f':'';label.title=required?'Authorization acknowledgement is required for this profile':'';if(required&&!authBox.checked){$('submit').title='Confirm authorization before starting this scan'}else{$('submit').title=''}};profileBox.addEventListener('change',syncAuthorization);authBox.addEventListener('change',syncAuthorization);syncAuthorization();
document.addEventListener('submit',event=>{if(event.target.id==='scan'&&['active','intrusive'].includes(profileBox.value)&&!authBox.checked){event.preventDefault();event.stopImmediatePropagation();$('status').textContent='Confirm authorization before starting an active or intrusive scan.'}},true);
const presets={passive_recon:{profile:'passive',threads:15,severity:'info',parameters:'',authorization:false,message:'Passive recon preset applied. Good for low-noise discovery.'},safe_web:{profile:'safe',threads:25,severity:'low',parameters:'',authorization:false,message:'Safe web app scan preset applied. Balanced coverage without mutation-heavy checks.'},active_params:{profile:'active',threads:20,severity:'medium',parameters:'id,search,q,page',authorization:false,message:'Active parameter testing preset applied. Confirm authorization before starting.'},intrusive_lab:{profile:'intrusive',threads:10,severity:'medium',parameters:'id,search,q,page,file,path,url',authorization:false,message:'Intrusive lab validation preset applied. Use only in an approved lab or owned target.'}};
function applyPreset(){const preset=presets[$('preset').value];if(!preset){$('status').textContent='Custom scan settings selected.';return}$('profile').value=preset.profile;$('threads').value=preset.threads;$('severity').value=preset.severity;$('parameters').value=preset.parameters;$('authorization').checked=preset.authorization;$('status').textContent=preset.message;syncAuthorization()}
$('applyPreset').onclick=applyPreset;$('preset').addEventListener('change',applyPreset);
function scanSettings(){return {target:$('target').value,profile:$('profile').value,threads:$('threads').value,severity:$('severity').value,parameters:$('parameters').value,authorization:$('authorization').checked,preset:$('preset').value}}
function saveScanSettings(){localStorage.setItem('neoscanner.scanSettings',JSON.stringify(scanSettings()))}
function restoreScanSettings(){try{const saved=JSON.parse(localStorage.getItem('neoscanner.scanSettings')||'{}');['target','profile','threads','severity','parameters','preset'].forEach(id=>{if(saved[id]!==undefined)$(id).value=saved[id]});if(saved.authorization!==undefined)$('authorization').checked=!!saved.authorization;syncAuthorization();if(saved.target)$('status').textContent='Restored last scan settings for '+saved.target}catch(e){}}
['target','profile','threads','severity','parameters','authorization','preset'].forEach(id=>$(id).addEventListener('input',saveScanSettings));restoreScanSettings();
function setPanelCollapsed(target,collapsed){$(target).classList.toggle('hide',collapsed);document.querySelectorAll('.collapse[data-target="'+target+'"]').forEach(b=>b.textContent=collapsed?'Expand':'Collapse');localStorage.setItem('neoscanner.panel.'+target,collapsed?'collapsed':'expanded')}
document.querySelectorAll('.collapse').forEach(b=>{const saved=localStorage.getItem('neoscanner.panel.'+b.dataset.target);setPanelCollapsed(b.dataset.target,saved==='collapsed');b.onclick=()=>setPanelCollapsed(b.dataset.target,!$(b.dataset.target).classList.contains('hide'))});
function severitySummary(sev){sev=sev||{};return ['critical','high','medium','low','info'].filter(k=>sev[k]).map(k=>'<span class="badge '+k+'">'+k+': '+sev[k]+'</span>').join(' ')||'<span class="muted">No findings</span>'}
async function loadHistory(){try{const records=await (await fetch('/api/history')).json();$('historyCount').textContent=records.length?records.length+' recent scans':'No previous scans';if(!records.length){$('history').innerHTML='<div class="empty">No scan history yet. Run a scan and this panel becomes your quick audit trail.</div>';return}$('history').innerHTML='<table><tr><th>Started</th><th>Target</th><th>Profile</th><th>Findings</th><th>Severity</th><th>Report</th></tr>'+records.slice(0,12).map(r=>{const target=(r.targets||[]).join(', ');const report=r.report?'/reports/'+r.report.split(/[\\\\/]/).pop():'';return '<tr><td>'+esc(new Date(r.started_at).toLocaleString())+'<br><span class="muted">'+esc(Math.round((r.duration_ms||0)/1000))+'s</span></td><td>'+link(target)+'</td><td>'+esc(r.profile||'unknown')+'</td><td><b>'+esc(r.findings||0)+'</b></td><td>'+severitySummary(r.severity)+'</td><td>'+(report?'<a class="link" href="'+esc(report)+'" target="_blank">Open report</a>':'<span class="muted">No report</span>')+'</td></tr>'}).join('')+'</table>'}catch(e){$('historyCount').textContent='History unavailable';$('history').innerHTML='<div class="empty">Could not load scan history: '+esc(e.message)+'</div>'}}
$('refreshHistory').onclick=loadHistory;loadHistory();setInterval(loadHistory,6000);
let reviews={};function reviewKey(f){return f.finding_id||f.fingerprint||f.name}
function reviewBadge(f){const r=reviews[reviewKey(f)];return r&&r.status?'<span class="badge info">'+esc(r.status.replace('_',' '))+'</span>':''}
async function loadReviews(){try{reviews=await (await fetch('/api/reviews')).json()}catch(e){reviews={}}reviewMetrics(state.findings);renderFindings()}
async function setReview(f,status){const r=await fetch('/api/reviews/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({finding_id:f.finding_id||'',fingerprint:f.fingerprint||'',status})});if(!r.ok){$('status').textContent='Could not save review state: '+await r.text();return}reviews=await r.json();$('reviewState').innerHTML=reviewBadge(f);reviewMetrics(state.findings);renderFindings()}
function selectedItems(){return state.findings.filter(f=>selectedFindings.has(reviewKey(f)))}
async function bulkReview(status){const items=selectedItems();if(!items.length){$('status').textContent='Select findings before using a bulk action.';return}for(const f of items){const r=await fetch('/api/reviews/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({finding_id:f.finding_id||'',fingerprint:f.fingerprint||'',status})});if(!r.ok){$('status').textContent='Bulk review failed: '+await r.text();return}reviews=await r.json()}$('status').textContent='Updated '+items.length+' selected findings.';reviewMetrics(state.findings);renderFindings();if(selected){$('reviewState').innerHTML=reviewBadge(selected)}}
function findingJSON(f){return JSON.stringify({finding_id:f.finding_id,fingerprint:f.fingerprint,severity:f.severity,confidence:f.confidence,name:f.name,template_id:f.template_id,matched_url:f.matched_url,method:f.method,parameter:f.parameter,cwe:f.cwe,cves:f.cves,cvss_score:f.cvss_score,cvss_vector:f.cvss_vector,impact:f.impact,evidence:f.evidence,remediation:f.remediation,references:f.references,request:f.request,response:f.response,baseline:f.baseline},null,2)}
function downloadText(name,text){const blob=new Blob([text],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
const detailWithActions=showDetail;showDetail=f=>{detailWithActions(f);if(!f)return;const affected=url(f.matched_url);$('details').querySelector('.detail-head').insertAdjacentHTML('afterend','<div class="row actionbar" style="margin:14px 0;flex-wrap:wrap"><button class="secondary" id="copyFindingId" type="button">Copy finding ID</button><button class="secondary" id="copyFindingJson" type="button">Copy JSON</button><button class="secondary" id="downloadFindingJson" type="button">Download JSON</button>'+(affected?'<a class="button secondary" id="openAffected" href="'+esc(affected)+'" target="_blank" rel="noreferrer">Open affected URL</a>':'')+'<button class="secondary" id="markReviewed" type="button">Mark reviewed</button><button class="secondary" id="markFalsePositive" type="button">Mark false positive</button><button class="secondary" id="clearReview" type="button">Clear review</button><span id="reviewState">'+reviewBadge(f)+'</span></div>');$('copyFindingId').onclick=()=>navigator.clipboard.writeText(f.finding_id||f.fingerprint||'');$('copyFindingJson').onclick=()=>navigator.clipboard.writeText(findingJSON(f));$('downloadFindingJson').onclick=()=>downloadText((f.finding_id||'finding')+'.json',findingJSON(f));$('markReviewed').onclick=()=>setReview(f,'reviewed');$('markFalsePositive').onclick=()=>setReview(f,'false_positive');$('clearReview').onclick=()=>setReview(f,'none')}
$('selectVisible').onclick=()=>{filtered().forEach(f=>selectedFindings.add(reviewKey(f)));renderFindings()};$('clearSelection').onclick=()=>{selectedFindings.clear();renderFindings()};$('bulkReviewed').onclick=()=>bulkReview('reviewed');$('bulkFalsePositive').onclick=()=>bulkReview('false_positive');$('bulkClearReview').onclick=()=>bulkReview('none');$('exportSelected').onclick=()=>{const items=selectedItems();if(!items.length){$('status').textContent='Select findings before exporting.';return}downloadText('selected-findings.json',JSON.stringify(items,null,2))}
function typingTarget(event){const tag=(event.target&&event.target.tagName||'').toLowerCase();return tag==='input'||tag==='textarea'||tag==='select'||event.target.isContentEditable}
function moveFinding(delta){const list=filtered();if(!list.length)return;let index=selected?list.findIndex(f=>f.finding_id===selected.finding_id):-1;index=(index+delta+list.length)%list.length;showDetail(list[index]);renderFindings();const row=document.querySelector('tr.selected-row');if(row)row.scrollIntoView({behavior:'smooth',block:'nearest'})}
document.addEventListener('keydown',event=>{if(event.key==='/'&&!typingTarget(event)){event.preventDefault();$('search').focus();$('search').select();return}if(typingTarget(event))return;if(event.key==='n'){event.preventDefault();moveFinding(1)}else if(event.key==='p'){event.preventDefault();moveFinding(-1)}else if(event.key==='r'&&selected){event.preventDefault();setReview(selected,'reviewed')}else if(event.key==='f'&&selected){event.preventDefault();setReview(selected,'false_positive')}});
loadReviews();
</script></body></html>`
