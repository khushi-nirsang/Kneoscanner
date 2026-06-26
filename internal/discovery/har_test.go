package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestImportHARKeepsOnlyMethodsAndURLs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.har")
	data := `{"log":{"entries":[{"request":{"method":"GET","url":"https://app.test/api/me","headers":[{"name":"Authorization","value":"secret"}],"postData":{"text":"password=hunter2"}}},{"request":{"method":"POST","url":"https://app.test/api/orders"}},{"request":{"method":"GET","url":"https://app.test/api/me"}}]}}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
	endpoints, err := ImportHAR(path)
	if err != nil || len(endpoints) != 2 || !containsEndpoint(endpoints, "https://app.test/api/me", "GET") || !containsEndpoint(endpoints, "https://app.test/api/orders", "POST") {
		t.Fatalf("unexpected HAR endpoints: %#v err=%v", endpoints, err)
	}
}
