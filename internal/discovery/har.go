package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ImportHAR reads only request methods and URLs. Bodies, headers, cookies, and
// response content deliberately remain out of the scanner's inventory.
func ImportHAR(path string) ([]Endpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read HAR file: %w", err)
	}
	var document struct {
		Log struct {
			Entries []struct {
				Request struct {
					Method string `json:"method"`
					URL    string `json:"url"`
				} `json:"request"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse HAR file: %w", err)
	}
	seen := make(map[string]Endpoint)
	for _, entry := range document.Log.Entries {
		method, url := strings.ToUpper(strings.TrimSpace(entry.Request.Method)), strings.TrimSpace(entry.Request.URL)
		if method == "" || url == "" {
			continue
		}
		key := method + " " + url
		seen[key] = Endpoint{URL: url, Method: method, Source: "har"}
	}
	endpoints := make([]Endpoint, 0, len(seen))
	for _, endpoint := range seen {
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].URL == endpoints[j].URL {
			return endpoints[i].Method < endpoints[j].Method
		}
		return endpoints[i].URL < endpoints[j].URL
	})
	return endpoints, nil
}
