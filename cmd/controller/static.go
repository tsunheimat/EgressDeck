package main

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// newSPAHandler serves the immutable frontend bundle. The controller routes
// every API request before this handler; the duplicate API guard prevents an
// accidental future composition change from returning HTML for an API error.
func newSPAHandler(directory string) (http.Handler, error) {
	root, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return nil, fmt.Errorf("open STATIC_DIR: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve STATIC_DIR: %w", err)
	}
	index, err := os.Stat(filepath.Join(root, "index.html"))
	if err != nil || !index.Mode().IsRegular() {
		return nil, fmt.Errorf("STATIC_DIR must contain a regular index.html")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := path.Clean(r.URL.Path)
		if cleanPath == "/api" || strings.HasPrefix(cleanPath, "/api/") || strings.ContainsAny(r.URL.Path, "\\\x00") {
			http.NotFound(w, r)
			return
		}
		for _, part := range strings.Split(r.URL.Path, "/") {
			if part == "." || part == ".." || strings.HasPrefix(part, ".") {
				http.NotFound(w, r)
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(cleanPath, "/")
		if name == "." || name == "" {
			name = "index.html"
		}
		resolved, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			if !os.IsNotExist(err) || path.Ext(name) != "" || name == "assets" || strings.HasPrefix(name, "assets/") {
				http.NotFound(w, r)
				return
			}
			resolved, err = filepath.EvalSymlinks(filepath.Join(root, "index.html"))
		}
		if err != nil || !insideStaticRoot(root, resolved) {
			http.NotFound(w, r)
			return
		}
		file, err := os.Open(resolved)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// The entrypoint must revalidate after an upgrade so it never points to
		// removed asset hashes. Hashed Vite assets can be cached immutably.
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
	}), nil
}

func insideStaticRoot(root, resolved string) bool {
	relative, err := filepath.Rel(root, resolved)
	return err == nil && relative != "." && fs.ValidPath(filepath.ToSlash(relative))
}
