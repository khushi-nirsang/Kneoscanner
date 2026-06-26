package gui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/khushi-nirsang/neoscanner/internal/config"
)

func TestReportLinksUseGUIReportRoutes(t *testing.T) {
	links := reportLinks(&config.Config{Output: "reports/security.json", HistoryFile: "reports/history.json", JSONReport: true, HTMLReport: true, PDFReport: true, SARIFReport: true})
	if len(links) != 5 || links[0].URL != "/reports/security.json" || links[1].URL != "/reports/security.html" || links[2].URL != "/reports/security.pdf" || links[3].URL != "/reports/security.sarif" || links[4].URL != "/reports/history.json" {
		t.Fatalf("unexpected report links: %#v", links)
	}
}

func TestStaticFrontendBundleExists(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "..", "web", "index.html"),
		filepath.Join("..", "..", "web", "styles.css"),
		filepath.Join("..", "..", "web", "app.js"),
		filepath.Join("..", "..", "assets", "kneoscanner-logo.png"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing static frontend file %s: %v", path, err)
		}
		if info.Size() == 0 {
			t.Fatalf("static frontend file is empty: %s", path)
		}
	}
}
func TestStaticFrontendUsesEventDrivenStatusUpdates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "web", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	js := string(data)
	for _, fragment := range []string{"new EventSource('/api/events')", "connectEvents()", "setInterval(poll, 15000)", "statusSignature", "scheduleStatusRefresh"} {
		if !strings.Contains(js, fragment) {
			t.Fatalf("static frontend is missing event-driven update fragment %q", fragment)
		}
	}
}

func TestWorkspaceIncludesEvidenceWorkflow(t *testing.T) {
	html := workspacePage()
	for _, fragment := range []string{"severityFilter", "confidenceFilter", "reviewFilter", "reviewMetrics", "review-metric", "triageProgress", "Triage progress", "Critical unreviewed", "High unreviewed", "focusMissingNotes", "notes-badge", "annotateNoteBadges", "workspace", "position:sticky", "Select a finding to inspect evidence", "findingPageSize", "prevFindingPage", "nextFindingPage", "findingPageStatus", "neoscanner.findingPageSize", "densityToggle", "Dense mode", "neoscanner.density", "body.compact", "advancedPolicy", "Advanced scan policy", "Additional targets", "targetList", "targetCount", "targets:$('targetList')", "authHeader", "cookieHeader", "crawlEnabled", "crawlMaxDepth", "policyTuning", "Engine tuning", "timeoutSeconds", "retryDelay", "requestDelay", "maxRespBytes", "followRedirects", "verifySSL", "allowExternal", "discoverOpenAPI", "discoverSitemap", "discoverScripts", "activeParamTesting", "activePostTesting", "Export policy JSON", "Import policy JSON", "collectPolicy", "applyPolicy", "neoscanner-policy.json", "configPanel", "/api/config", "Refresh config", "Transport", "Active coverage", "templatePanel", "/api/templates", "Template inventory", "templateSearch", "templateSeverity", "templateStatus", "Refresh templates", "filterChips", "renderFilterChips", "Scan preset", "Passive recon", "Safe web app scan", "Active parameter testing", "Intrusive lab validation", "applyPreset", "saveScanSettings", "restoreScanSettings", "neoscanner.scanSettings", "collapse", "setPanelCollapsed", "neoscanner.panel.", "scanPanel", "historyPanel", "Shortcuts:", "moveFinding", "typingTarget", "selected-row", "scrollIntoView", "Unreviewed only", "False positives", "Has analyst notes", "Missing analyst notes", "has_notes", "missing_notes", "Verification evidence", "Baseline", "Copy cURL", "request", "response", "Reset filters", "Technologies", "Scanning for", "Copied", "Escape", "Filter findings by", "syncAuthorization", "Confirm authorization before starting", "Scan history", "/api/history", "Refresh history", "/api/reviews", "/api/reviews/update", "Analyst notes", "analyst_notes", "findingNotes", "notesState", "notesUpdated", "reviewUpdatedText", "Last updated", "Not saved yet", "Unsaved changes", "Saving…", "Save failed", "hasUnsavedNotes", "beforeunload", "notesSaveTimer", "setTimeout(()=>saveFindingNotes(f),1200)", "detailEditing", "ctrlKey", "metaKey", "Save notes", "saveFindingNotes", "copyEvidencePane", "Copy pane", "evidenceBundle", "Copy evidence bundle", "Copied full evidence bundle", "Copied '+id+' evidence pane", "Copy finding ID", "Copy finding link", "#finding=", "openHashFinding", "hashchange", "Copy issue template", "issueMarkdown", "## Analyst notes", "## Remediation", "## Evidence", "Copy JSON", "Download JSON", "Open affected URL", "Mark reviewed", "Mark false positive", "Clear review", "bulkActions", "Select visible", "Mark selected reviewed", "Export selected JSON", "Export visible JSON", "Export visible CSV", "Copy visible summary", "visibleMarkdown", "KneoScanner visible findings summary", "review_status", "selectedFindings"} {
		if !strings.Contains(html, fragment) {
			t.Fatalf("workspace page is missing %q", fragment)
		}
	}
}

func TestNormalizeTargetsDeduplicatesAndSplitsCommonSeparators(t *testing.T) {
	targets := normalizeTargets("https://a.test", []string{"https://b.test\nhttps://a.test, https://c.test;https://b.test"})
	want := []string{"https://a.test", "https://b.test", "https://c.test"}
	if strings.Join(targets, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected targets: %#v", targets)
	}
}

func TestWorkspaceDecorationPreservesBasePageAndAddsEnhancements(t *testing.T) {
	html := decorateWorkspacePage("<html><head></head><body><div id=\"reports\"></div><script>const base=true;</script></body></html>")
	for _, fragment := range []string{"const base=true;", "body.compact", "densityToggle", "exportVisibleJson", "copyIssueTemplate", "findingNotes", "copyEvidencePane", "copyEvidenceBundle", "triageProgress", "advancedPolicy", "templatePanel", "exportPolicy"} {
		if !strings.Contains(html, fragment) {
			t.Fatalf("decorated page is missing %q", fragment)
		}
	}
}

func TestWorkspaceIncludesApplicationShellNavigation(t *testing.T) {
	html := workspacePage()
	for _, fragment := range []string{"app-shell", "app-frame", "app-sidebar", "app-nav", "app-topbar", "app-view", "app-split-view", "neoScannerActivateView", "Scan setup", "Runtime config", "Security operations workspace"} {
		if !strings.Contains(html, fragment) {
			t.Fatalf("workspace app shell is missing %q", fragment)
		}
	}
}

func TestWorkspacePreservesEvidenceTabsAndShowsTranscriptURLs(t *testing.T) {
	html := workspacePage()
	for _, fragment := range []string{"__kneoScannerTabMemory", "activePane", "__kneoScannerTranscriptUpgrade", "Final URL", "Request body", "Response body"} {
		if !strings.Contains(html, fragment) {
			t.Fatalf("workspace transcript UX is missing %q", fragment)
		}
	}
}

func TestReviewStorePersistsAndClearsFindingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reviews.json")
	records, err := saveReview(path, reviewRecord{FindingID: "finding-1", Fingerprint: "fp-1", Status: "reviewed", Notes: "confirmed by analyst"})
	if err != nil {
		t.Fatal(err)
	}
	if records["finding-1"].Status != "reviewed" || records["finding-1"].UpdatedAt.IsZero() {
		t.Fatalf("review was not persisted correctly: %#v", records)
	}
	loaded, err := loadReviews(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded["finding-1"].Fingerprint != "fp-1" || loaded["finding-1"].Notes != "confirmed by analyst" {
		t.Fatalf("unexpected loaded review: %#v", loaded)
	}
	records, err = saveReview(path, reviewRecord{FindingID: "finding-1", Status: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := records["finding-1"]; ok {
		t.Fatalf("review was not cleared: %#v", records)
	}
}
