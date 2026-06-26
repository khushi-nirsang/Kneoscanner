package utils

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

type HTTPClient struct {
	Client   *http.Client
	Options  HTTPOptions
	requests chan struct{}
}
type HTTPOptions struct {
	Timeout          time.Duration
	UserAgent        string
	DefaultHeaders   map[string]string
	FollowRedirects  bool
	MaxRedirects     int
	VerifyTLS        bool
	Retries          int
	RetryDelay       time.Duration
	RequestDelay     time.Duration
	MaxResponseBytes int64
}
type RequestOptions struct {
	Timeout            time.Duration
	FollowRedirects    *bool
	ScopeURL           string
	SkipDefaultHeaders bool
}
type Response struct {
	*http.Response
	BodyContent, RequestedURL, FinalURL string
	BodySize                            int64
	Truncated                           bool
	Attempts                            int
	Duration                            time.Duration
}

func NewHTTPClient(timeout int) *HTTPClient {
	options := DefaultHTTPOptions()
	options.Timeout = time.Duration(timeout) * time.Second
	return NewHTTPClientWithOptions(options)
}
func DefaultHTTPOptions() HTTPOptions {
	return HTTPOptions{Timeout: 10 * time.Second, UserAgent: "KneoScanner/1.0", FollowRedirects: true, MaxRedirects: 5, VerifyTLS: true, Retries: 2, RetryDelay: 500 * time.Millisecond, MaxResponseBytes: 2 * 1024 * 1024}
}
func NewHTTPClientWithOptions(options HTTPOptions) *HTTPClient {
	defaults := DefaultHTTPOptions()
	if options.Timeout <= 0 {
		options.Timeout = defaults.Timeout
	}
	if options.UserAgent == "" {
		options.UserAgent = defaults.UserAgent
	}
	if options.MaxRedirects <= 0 {
		options.MaxRedirects = defaults.MaxRedirects
	}
	if options.Retries < 0 {
		options.Retries = 0
	}
	if options.RetryDelay < 0 {
		options.RetryDelay = 0
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = defaults.MaxResponseBytes
	}
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: !options.VerifyTLS}, MaxIdleConns: 100, MaxIdleConnsPerHost: 50, IdleConnTimeout: 30 * time.Second}
	return &HTTPClient{Client: &http.Client{Timeout: options.Timeout, Transport: transport, Jar: jar, CheckRedirect: redirectPolicy(options.FollowRedirects, options.MaxRedirects, "")}, Options: options}
}

// SetMaxConcurrentRequests applies one scanner-wide request budget.
func (h *HTTPClient) SetMaxConcurrentRequests(max int) {
	if max <= 0 {
		max = 1
	}
	h.requests = make(chan struct{}, max)
}
func (h *HTTPClient) Get(rawURL string) (*Response, error) {
	return h.GetContext(context.Background(), rawURL)
}
func (h *HTTPClient) GetContext(ctx context.Context, rawURL string) (*Response, error) {
	return h.DoWithOptionsContext(ctx, http.MethodGet, rawURL, nil, "", RequestOptions{})
}
func (h *HTTPClient) GetScopedContext(ctx context.Context, scopeURL, rawURL string) (*Response, error) {
	return h.DoWithOptionsContext(ctx, http.MethodGet, rawURL, nil, "", RequestOptions{ScopeURL: scopeURL})
}
func (h *HTTPClient) Do(method, rawURL string, headers map[string]string, body string) (*Response, error) {
	return h.DoWithOptionsContext(context.Background(), method, rawURL, headers, body, RequestOptions{})
}
func (h *HTTPClient) DoWithOptions(method, rawURL string, headers map[string]string, body string, requestOptions RequestOptions) (*Response, error) {
	return h.DoWithOptionsContext(context.Background(), method, rawURL, headers, body, requestOptions)
}
func (h *HTTPClient) DoWithOptionsContext(ctx context.Context, method, rawURL string, headers map[string]string, body string, requestOptions RequestOptions) (*Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	options := h.Options
	if requestOptions.Timeout > 0 {
		options.Timeout = requestOptions.Timeout
	}
	if requestOptions.FollowRedirects != nil {
		options.FollowRedirects = *requestOptions.FollowRedirects
	}
	client := *h.Client
	client.Timeout = options.Timeout
	client.CheckRedirect = redirectPolicy(options.FollowRedirects, options.MaxRedirects, requestOptions.ScopeURL)
	attempts := options.Retries + 1
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		resp, err := h.doOnce(ctx, &client, method, rawURL, headers, body, options, requestOptions.SkipDefaultHeaders)
		if err == nil && !shouldRetryStatus(method, resp.StatusCode) {
			resp.Attempts = attempt
			return resp, nil
		}
		if err == nil {
			lastErr = errors.New("retryable HTTP response")
			if attempt == attempts {
				resp.Attempts = attempt
				return resp, nil
			}
		} else {
			lastErr = err
			if attempt == attempts || !isSafeRetryMethod(method) {
				return nil, err
			}
		}
		if options.RetryDelay > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(options.RetryDelay):
			}
		}
	}
	return nil, lastErr
}
func (h *HTTPClient) doOnce(ctx context.Context, client *http.Client, method, rawURL string, headers map[string]string, body string, options HTTPOptions, skipDefaultHeaders bool) (*Response, error) {
	if h.requests != nil {
		select {
		case h.requests <- struct{}{}:
			defer func() { <-h.requests }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if options.RequestDelay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(options.RequestDelay):
		}
	}
	var reader io.Reader
	if body != "" {
		reader = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", options.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Connection", "keep-alive")
	if !skipDefaultHeaders {
		for key, value := range options.DefaultHeaders {
			req.Header.Set(key, value)
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return nil, gzErr
		}
		defer gz.Close()
		reader = gz
	}
	bodyBytes, readErr := io.ReadAll(io.LimitReader(reader, options.MaxResponseBytes+1))
	if readErr != nil {
		return nil, readErr
	}
	truncated := int64(len(bodyBytes)) > options.MaxResponseBytes
	if truncated {
		bodyBytes = bodyBytes[:options.MaxResponseBytes]
	}
	return &Response{Response: resp, BodyContent: string(bodyBytes), RequestedURL: rawURL, FinalURL: resp.Request.URL.String(), BodySize: int64(len(bodyBytes)), Truncated: truncated, Duration: time.Since(started)}, nil
}
func redirectPolicy(follow bool, max int, scopeURL string) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if !follow || len(via) > max {
			return http.ErrUseLastResponse
		}
		if scopeURL != "" && !sameOrigin(scopeURL, request.URL.String()) {
			return http.ErrUseLastResponse
		}
		return nil
	}
}
func sameOrigin(left, right string) bool {
	a, errA := url.Parse(left)
	b, errB := url.Parse(right)
	return errA == nil && errB == nil && a.Scheme == b.Scheme && a.Hostname() == b.Hostname() && a.Port() == b.Port()
}
func isSafeRetryMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}
func shouldRetryStatus(method string, status int) bool {
	return isSafeRetryMethod(method) && (status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500)
}
