package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"sort"

	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

// HTTPTranscript is a bounded, sanitized request/response record. It gives a
// reviewer enough information to validate a finding without allowing reports
// to become an accidental secret store.
type HTTPTranscript struct {
	Method     string              `json:"method"`
	URL        string              `json:"url"`
	FinalURL   string              `json:"final_url,omitempty"`
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       string              `json:"body,omitempty"`
	BodySHA256 string              `json:"body_sha256,omitempty"`
	BodySize   int64               `json:"body_size,omitempty"`
	Truncated  bool                `json:"truncated,omitempty"`
	DurationMS int64               `json:"duration_ms,omitempty"`
	Redacted   bool                `json:"redacted,omitempty"`
}

var sensitiveName = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session|credential|private[_-]?key)`)
var sensitivePair = regexp.MustCompile(`(?i)("?(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session|credential)"?\s*[:=]\s*)([^,\s&}\]]+)`)

func (s *Scanner) transcript(method, requestURL, requestBody string, response *utils.Response) *HTTPTranscript {
	maxBytes := s.evidenceMaxBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	redact := s.redactSensitiveData
	requestHeaders := http.Header{}
	if response != nil && response.Response != nil && response.Request != nil {
		requestHeaders = response.Request.Header
	}
	request := transcript(method, requestURL, "", 0, requestHeaders, requestBody, 0, false, 0, maxBytes, redact)
	if response == nil || response.Response == nil {
		return request
	}
	responseHeaders := response.Header
	responseBody := response.BodyContent
	result := transcript(method, response.RequestedURL, response.FinalURL, response.StatusCode, responseHeaders, responseBody, response.BodySize, response.Truncated, response.Duration.Milliseconds(), maxBytes, redact)
	// The request is embedded in the response transcript only for a single
	// compact record. The caller retains it as the finding Request field.
	_ = request
	return result
}

func (s *Scanner) requestTranscript(method, requestURL, requestBody string, response *utils.Response) *HTTPTranscript {
	maxBytes := s.evidenceMaxBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	headers := http.Header{}
	if response != nil && response.Response != nil && response.Request != nil {
		headers = response.Request.Header
	}
	return transcript(method, requestURL, "", 0, headers, requestBody, int64(len(requestBody)), false, 0, maxBytes, s.redactSensitiveData)
}

func transcript(method, rawURL, finalURL string, status int, headers http.Header, body string, bodySize int64, truncated bool, durationMS, maxBytes int64, redact bool) *HTTPTranscript {
	copyHeaders, redactedHeaders := sanitizedHeaders(headers, redact)
	redactedBody := false
	if redact {
		body, redactedBody = redactBody(body)
	}
	body, bodyWasTruncated := boundedBody(body, maxBytes)
	sum := sha256.Sum256([]byte(body))
	return &HTTPTranscript{Method: method, URL: rawURL, FinalURL: finalURL, StatusCode: status, Headers: copyHeaders, Body: body, BodySHA256: hex.EncodeToString(sum[:]), BodySize: bodySize, Truncated: truncated || bodyWasTruncated, DurationMS: durationMS, Redacted: redactedHeaders || redactedBody}
}

func sanitizedHeaders(headers http.Header, redact bool) (map[string][]string, bool) {
	if len(headers) == 0 {
		return nil, false
	}
	result := make(map[string][]string, len(headers))
	redacted := false
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := append([]string(nil), headers.Values(key)...)
		if redact && sensitiveName.MatchString(key) {
			values = []string{"[REDACTED]"}
			redacted = true
		}
		result[key] = values
	}
	return result, redacted
}

func boundedBody(body string, maxBytes int64) (string, bool) {
	if maxBytes <= 0 || int64(len(body)) <= maxBytes {
		return body, false
	}
	return body[:maxBytes], true
}

func redactBody(body string) (string, bool) {
	if body == "" {
		return body, false
	}
	redacted := sensitivePair.ReplaceAllString(body, "$1[REDACTED]")
	if redacted != body {
		return redacted, true
	}
	values, err := url.ParseQuery(body)
	if err != nil || len(values) == 0 {
		return body, false
	}
	changed := false
	for key := range values {
		if sensitiveName.MatchString(key) {
			values.Set(key, "[REDACTED]")
			changed = true
		}
	}
	if !changed {
		return body, false
	}
	return values.Encode(), true
}
