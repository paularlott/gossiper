package server

import (
	"compress/gzip"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	webassets "github.com/paularlott/gossiper/web"
)

// apiDocsCSP lets Redoc run from this server only: its script is a built asset, it styles itself with inline styles,
// and it fetches nothing but /api/openapi.json (no telemetry, fonts or icons from elsewhere).
const apiDocsCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// apiDocs serves the API reference page (web/api-docs/index.html, built into dist by Vite).
func apiDocs(w http.ResponseWriter, _ *http.Request) {
	b, err := fs.ReadFile(webassets.Dist, "dist/api-docs/index.html")
	if err != nil {
		http.Error(w, "The API reference was not built into this binary.", http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache") // it names the current hashed assets
	h.Set("Content-Security-Policy", apiDocsCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b)
}

// apiDocsAsset serves a script or stylesheet of the API reference. The build stores them gzipped: they go out as
// they are to a client that accepts gzip, decompressed to any other. Their names carry their content's hash, so they
// are cached for good.
func apiDocsAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if name == "" || strings.ContainsAny(name, "/\\") || strings.HasPrefix(name, ".") {
		http.NotFound(w, r)
		return
	}
	f, err := webassets.Dist.Open("dist/assets/" + name + ".gz")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	h := w.Header()
	h.Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Add("Vary", "Accept-Encoding")
	if acceptsGzip(r) {
		h.Set("Content-Encoding", "gzip")
		_, _ = io.Copy(w, f)
		return
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		http.Error(w, "corrupt asset", http.StatusInternalServerError)
		return
	}
	_, _ = io.Copy(w, zr)
}

// acceptsGzip reports whether the request's Accept-Encoding allows gzip (and does not refuse it with q=0).
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if c := strings.ToLower(strings.TrimSpace(coding)); c != "gzip" && c != "*" {
			continue
		}
		q := strings.ReplaceAll(strings.ToLower(params), " ", "")
		return q != "q=0" && q != "q=0.0" && q != "q=0.00" && q != "q=0.000"
	}
	return false
}

// openAPIDocument serves the OpenAPI description of the admin API: web/openapi/openapi.yaml, bundled into
// dist/openapi.json by the web build.
func openAPIDocument(w http.ResponseWriter, _ *http.Request) {
	b, err := fs.ReadFile(webassets.Dist, "dist/openapi.json")
	if err != nil {
		writeJSON(w, http.StatusNotFound, apiError{Error: "The OpenAPI document was not built into this binary."})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b)
}
