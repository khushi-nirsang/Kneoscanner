package discovery

import (
	"context"
	"encoding/xml"
	"net/url"
	"strings"

	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

// DiscoverSitemap collects same-origin URLs from sitemap.xml. Missing or
// malformed sitemap files are normal and do not fail a crawl.
func DiscoverSitemap(ctx context.Context, client *utils.HTTPClient, target string) []string {
	response, err := client.GetScopedContext(ctx, target, resolveSpecURL(target, "/sitemap.xml"))
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil
	}
	var document struct {
		URLs []struct {
			Location string `xml:"loc"`
		} `xml:"url"`
	}
	if xml.Unmarshal([]byte(response.BodyContent), &document) != nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, entry := range document.URLs {
		raw := strings.TrimSpace(entry.Location)
		parsed, err := url.Parse(raw)
		root, rootErr := url.Parse(target)
		if err == nil && rootErr == nil && strings.EqualFold(parsed.Hostname(), root.Hostname()) && parsed.Port() == root.Port() {
			parsed.Fragment = ""
			seen[parsed.String()] = struct{}{}
		}
	}
	return sortedStrings(seen)
}
