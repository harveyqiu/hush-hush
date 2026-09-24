package main

import (
	"embed"
	"io/fs"
	"net/http"
)

// The admin web UI: static files embedded in the binary, no build step and
// no third-party code. It talks to the same JSON API as every other client,
// authenticating with an admin token the operator pastes in; the token is
// kept in sessionStorage (this tab only) and sent as a bearer header, so
// there are no cookies and no CSRF surface.

//go:embed ui
var uiFiles embed.FS

// uiCSP forbids inline script and style and any third-party origin, so a
// secret or token name rendered by the page can't turn into markup or
// script even if escaping were ever missed.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

func (s *server) uiRoutes(mux *http.ServeMux) {
	// fs.Sub only fails for an invalid path; "ui" is a constant.
	sub, _ := fs.Sub(uiFiles, "ui")
	files := http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))
	mux.Handle("GET /ui/", uiHeaders(files))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
}

func uiHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", uiCSP)
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}
