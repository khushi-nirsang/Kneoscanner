package utils

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
)

type HTTPClient struct {
	Client *http.Client
}

type Response struct {
	*http.Response
	BodyContent string
}

func NewHTTPClient(timeout int) *HTTPClient {

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
	}

	return &HTTPClient{
		Client: &http.Client{
			Timeout:   time.Duration(timeout) * time.Second,
			Transport: transport,
		},
	}
}

func (h *HTTPClient) Get(url string) (*Response, error) {
	return h.Do("GET", url, nil, "")
}

func (h *HTTPClient) Do(
	method string,
	url string,
	headers map[string]string,
	body string,
) (*Response, error) {

	var reader io.Reader

	if body != "" {
		reader = bytes.NewBufferString(body)
	}

	req, err := http.NewRequest(
		method,
		url,
		reader,
	)

	if err != nil {
		return nil, err
	}

	req.Header.Set(
		"User-Agent",
		"NeoScanner/1.0",
	)

	req.Header.Set(
		"Accept",
		"*/*",
	)

	req.Header.Set(
		"Accept-Encoding",
		"gzip",
	)

	req.Header.Set(
		"Connection",
		"keep-alive",
	)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := h.Client.Do(req)

	if err != nil {
		return nil, err
	}

	var bodyBytes []byte

	if resp.Header.Get("Content-Encoding") == "gzip" {

		gzipReader, err := gzip.NewReader(resp.Body)

		if err == nil {
			bodyBytes, _ = io.ReadAll(gzipReader)
			gzipReader.Close()
		}
	} else {
		bodyBytes, _ = io.ReadAll(resp.Body)
	}

	resp.Body.Close()

	color.Green(
		"[+] %s %s -> %d",
		method,
		url,
		resp.StatusCode,
	)

	return &Response{
		Response:    resp,
		BodyContent: string(bodyBytes),
	}, nil
}