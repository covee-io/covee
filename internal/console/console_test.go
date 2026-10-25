package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsoleRoutesServeHTMLWithoutRedirect(t *testing.T) {
	handler := Handler()
	for _, path := range []string{"/", "/index.html", "/overview", "/devices", "/users", "/keys", "/gateway", "/policy", "/audit"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<title>Covee") {
				t.Fatalf("route did not serve HTML: code=%d location=%q", w.Code, w.Header().Get("Location"))
			}
			if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
				t.Fatal("console is missing its self-only script policy")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("console must not cache authenticated view state")
			}
			// Under no-referrer, Safari sends the console's same-origin POSTs
			// (sign-in among them) with "Origin: null", which the management
			// service refuses: the sign-in failed on iPhone.
			if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
				t.Fatalf("console Referrer-Policy %q", got)
			}
		})
	}
}

func TestConsoleOnlyServesKnownAssets(t *testing.T) {
	handler := Handler()
	for _, test := range []struct {
		method string
		path   string
		code   int
	}{{"GET", "/app.css", 200}, {"GET", "/app.js", 200}, {"HEAD", "/", 200}, {"GET", "/api/session", 404}, {"GET", "/assets/", 404}, {"GET", "/../console.go", 404}, {"POST", "/", 405}} {
		t.Run(test.method+test.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
			if w.Code != test.code {
				t.Fatalf("got %d, want %d", w.Code, test.code)
			}
			if test.method == http.MethodHead && w.Body.Len() != 0 {
				t.Fatal("HEAD returned a body")
			}
		})
	}
}
