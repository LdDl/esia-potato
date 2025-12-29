package httpapi

import (
	"embed"
	"net/http"
)

//go:embed docs/swagger.json docs/index.html
var docsFS embed.FS

// HandleDocsUI RapiDoc UI endpoint
func HandleDocsUI(w http.ResponseWriter, r *http.Request) {
	data, err := docsFS.ReadFile("docs/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "index.html not found")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// HandleDocsJSON Swagger JSON endpoint
func HandleDocsJSON(w http.ResponseWriter, r *http.Request) {
	data, err := docsFS.ReadFile("docs/swagger.json")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "swagger.json not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
