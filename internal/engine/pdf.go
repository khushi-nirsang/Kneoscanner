package engine

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// writePDFReport creates a self-contained, portable PDF using only the Go
// standard library. Keeping it in-process means the released scanner does not
// depend on Python, a browser, or a third-party PDF viewer.
func writePDFReport(outputFile string, items []ScanResult) error {
	lines := []string{"KneoScanner Detailed Security Report", "", fmt.Sprintf("Total findings: %d", len(items)), ""}
	for index, item := range items {
		lines = append(lines,
			fmt.Sprintf("Finding %d - %s [%s]", index+1, item.Name, strings.ToUpper(item.Severity)),
			"Target: "+item.Target,
			"Request: "+item.Method+" "+item.MatchedURL,
			"Final URL: "+item.FinalURL,
			valueOr(item.Parameter, "Parameter: not applicable", "Parameter: "),
			valueOr(item.Payload, "Payload: none", "Payload: "),
			"CVE: "+cveText(item.CVEs),
			"Remediation: "+remediationFor(item),
		)
		for _, proof := range item.Evidence {
			lines = append(lines, "Proof: "+proof)
		}
		for _, ref := range item.References {
			lines = append(lines, "Reference: "+ref)
		}
		lines = append(lines, "")
	}

	pages := paginatePDFLines(lines, 52, 96)
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", ""}
	pageIDs := make([]int, 0, len(pages))
	for _, page := range pages {
		pageIDs = append(pageIDs, len(objects)+1)
		objects = append(objects, "", pdfStream(page))
	}
	kids := make([]string, 0, len(pageIDs))
	for _, id := range pageIDs {
		kids = append(kids, fmt.Sprintf("%d 0 R", id))
	}
	objects[1] = "<< /Type /Pages /Kids [" + strings.Join(kids, " ") + "] /Count " + fmt.Sprint(len(pageIDs)) + " >>"
	for i, pageID := range pageIDs {
		objects[pageID-1] = fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", len(objects)+1, pageID+1)
		_ = i
	}
	objects = append(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	var document bytes.Buffer
	document.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects)+1)
	for i, object := range objects {
		offsets[i+1] = document.Len()
		fmt.Fprintf(&document, "%d 0 obj\n%s\nendobj\n", i+1, object)
	}
	xref := document.Len()
	fmt.Fprintf(&document, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&document, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&document, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return os.WriteFile(outputFile, document.Bytes(), 0644)
}

func valueOr(value, empty, prefix string) string {
	if value == "" {
		return empty
	}
	return prefix + value
}
func cveText(cves []string) string {
	if len(cves) == 0 {
		return "not applicable - no affected product/version identified"
	}
	return strings.Join(cves, ", ")
}
func remediationFor(item ScanResult) string {
	if item.Remediation != "" {
		return item.Remediation
	}
	switch item.TemplateID {
	case "xss-probe":
		return "Apply context-aware output encoding and enforce a restrictive Content-Security-Policy."
	case "authentication-bypass":
		return "Use parameterized database queries, reject malformed credentials, and verify authentication server-side."
	case "csrf-discovered-form":
		return "Add a cryptographically random, server-validated CSRF token and enforce SameSite cookies."
	default:
		return "Validate the finding, patch the affected component, and add a regression test."
	}
}

func paginatePDFLines(lines []string, maxLines, maxWidth int) [][]string {
	pages, page := make([][]string, 0), make([]string, 0, maxLines)
	for _, line := range lines {
		for _, wrapped := range wrapPDFLine(line, maxWidth) {
			if len(page) == maxLines {
				pages = append(pages, page)
				page = make([]string, 0, maxLines)
			}
			page = append(page, wrapped)
		}
	}
	if len(page) > 0 {
		pages = append(pages, page)
	}
	return pages
}
func wrapPDFLine(line string, width int) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return []string{""}
	}
	var out []string
	for len(line) > width {
		cut := strings.LastIndex(line[:width+1], " ")
		if cut < 1 {
			cut = width
		}
		out = append(out, line[:cut])
		line = strings.TrimSpace(line[cut:])
	}
	return append(out, line)
}
func pdfStream(lines []string) string {
	var b strings.Builder
	b.WriteString("BT\n/F1 9 Tf\n50 760 Td\n")
	for _, line := range lines {
		b.WriteString("(")
		b.WriteString(pdfEscape(line))
		b.WriteString(") Tj\n0 -14 Td\n")
	}
	b.WriteString("ET\n")
	content := b.String()
	return fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content)
}
func pdfEscape(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '?'
		}
		return r
	}, value)
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "(", "\\(")
	return strings.ReplaceAll(value, ")", "\\)")
}
