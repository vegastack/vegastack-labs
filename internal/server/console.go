package server

import (
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/consoleassets"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type consoleHandler struct {
	files    fs.FS
	manifest consoleassets.Manifest
}

func NewConsoleHandler(files fs.FS, manifest consoleassets.Manifest) (http.Handler, error) {
	if files == nil || manifest.SchemaVersion != 1 || manifest.ContentSecurityPolicy == "" || len(manifest.Files) == 0 {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "console-assets", false)
	}
	if index, ok := manifest.Files["index.html"]; !ok || index.ContentType != "text/html; charset=utf-8" {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "console-assets", false)
	}
	return &consoleHandler{files: files, manifest: manifest}, nil
}

func (handler *consoleHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler.securityHeaders(writer)
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}
	name, status := consoleAssetName(request)
	if status != 0 {
		http.Error(writer, http.StatusText(status), status)
		return
	}
	name, ok := handler.resolve(name)
	if !ok {
		http.Error(writer, "NOT_FOUND", http.StatusNotFound)
		return
	}
	asset, ok := handler.manifest.Files[name]
	if !ok {
		http.Error(writer, "NOT_FOUND", http.StatusNotFound)
		return
	}
	content, err := fs.ReadFile(handler.files, name)
	if err != nil || int64(len(content)) != asset.Size {
		http.Error(writer, "INTEGRITY_FAILURE", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", asset.ContentType)
	writer.Header().Set("ETag", `"sha256:`+asset.SHA256+`"`)
	if asset.Immutable {
		writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		writer.Header().Set("Cache-Control", "no-store")
	}
	if request.Header.Get("If-None-Match") == writer.Header().Get("ETag") {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.Header().Set("Content-Length", strconv.FormatInt(asset.Size, 10))
	writer.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = writer.Write(content)
	}
}

func (handler *consoleHandler) securityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Content-Security-Policy", handler.manifest.ContentSecurityPolicy)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
}

func consoleAssetName(request *http.Request) (string, int) {
	raw := strings.ToLower(request.URL.EscapedPath())
	if strings.Contains(raw, "%2e") || strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") || strings.Contains(raw, "%00") || strings.Contains(raw, "%25") {
		return "", http.StatusBadRequest
	}
	decoded := request.URL.Path
	if !utf8.ValidString(decoded) || strings.ContainsAny(decoded, "\\\x00") {
		return "", http.StatusBadRequest
	}
	trimmed := strings.Trim(decoded, "/")
	if trimmed == "" {
		return "index.html", 0
	}
	if path.Clean(trimmed) != trimmed || strings.HasPrefix(trimmed, ".") || strings.Contains(trimmed, "/../") {
		return "", http.StatusBadRequest
	}
	return trimmed, 0
}

func (handler *consoleHandler) resolve(name string) (string, bool) {
	if _, ok := handler.manifest.Files[name]; ok {
		return name, true
	}
	if path.Ext(name) == "" {
		if _, ok := handler.manifest.Files[name+".html"]; ok {
			return name + ".html", true
		}
	}
	return "", false
}

func NewBrowserHandler(apiHandler, staticHandler http.Handler, authenticator *BrowserAuthenticator) (http.Handler, error) {
	if apiHandler == nil || staticHandler == nil || authenticator == nil {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "browser-handler", false)
	}
	protectedAPI := authenticator.Wrap(apiHandler)
	protectedAssets := authenticator.WrapAssets(staticHandler)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api" || strings.HasPrefix(request.URL.Path, "/api/") {
			if !api.RemoteReadRequestAllowed(request.Method, request.URL.Path) {
				writer.Header().Set("Cache-Control", "no-store")
				writer.Header().Set("X-Content-Type-Options", "nosniff")
				http.Error(writer, "NOT_FOUND", http.StatusNotFound)
				return
			}
			protectedAPI.ServeHTTP(writer, request)
			return
		}
		protectedAssets.ServeHTTP(writer, request)
	}), nil
}
