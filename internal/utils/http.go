package utils

import (
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
)

type HTTPClient struct {
	Client *http.Client
}

func NewHTTPClient(timeout int) *HTTPClient {
	return &HTTPClient{
		Client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

type Response struct {
	*http.Response
	BodyContent string
}

func (h *HTTPClient) Get(url string) (*Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "NeoScanner/1.0")

	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	bodyStr := string(bodyBytes)

	color.Green("[+] Connected to %s → Status: %d", url, resp.StatusCode)

	return &Response{
		Response:    resp,
		BodyContent: bodyStr,
	}, nil
}