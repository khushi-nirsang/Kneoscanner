package utils

import (
	"io"
	"net/http"
	"time"
)

func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
	}
}

func Get(url string) (*http.Response, error) {
	client := NewHTTPClient()
	return client.Get(url)
}
