// Package console serves the self-contained Covee administration interface.
package console

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"time"
)

//go:embed assets/*
var assets embed.FS

// Handler returns an HTTP handler for the console and its local static assets.
// API routes must be registered separately by the caller.
func Handler() http.Handler {
	root, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err)
	}
	static := http.FileServer(http.FS(root))
	index, err := fs.ReadFile(root, "index.html")
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/", "/index.html", "/overview", "/devices", "/users", "/keys", "/gateway", "/policy", "/audit":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
		case "/app.css", "/app.js":
			static.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
