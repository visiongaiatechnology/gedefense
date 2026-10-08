// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"net/http"
	"time"
)

// The product mark, embedded rather than read from disk.
//
// The login page drew its own mark in CSS - a rotated square with a green dot - which is
// a placeholder, not the product's identity. Showing the real mark would normally mean
// shipping an asset and a route for it, and the gateway has no asset directory: it is a
// single binary with a login page, a proxy and two health endpoints.
//
// Embedding keeps that shape. The image travels inside the binary, so there is nothing to
// deploy alongside it, nothing to keep in step with the control plane's copy, and no file
// path to validate - which matters on the one page that is reachable before anybody has
// authenticated. The page already claims "zero external assets" in its own footer; this is
// what makes that claim true for its own mark as well.
//
//go:embed gedefense-logo.png
var productLogo []byte

// productLogoETag identifies these exact bytes so a client can revalidate instead of
// refetching. It is derived from the content rather than from a version string: two builds
// carrying the same mark share it, and a mark that changes under an unchanged version
// still gets a new one.
var productLogoETag = func() string {
	sum := sha256.Sum256(productLogo)
	return `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`
}()

// logo serves the embedded mark. It is deliberately unauthenticated: the login page needs
// it before a session exists, and it discloses nothing beyond the product's identity.
//
// ServeContent does the work that is easy to get wrong by hand - conditional requests,
// range requests and Content-Length - against a reader over the embedded bytes. The ETag
// has to be set before the call, because that is where ServeContent looks for it, and
// without it a conditional request is answered with the whole image.
func (g *gateway) logo(w http.ResponseWriter, r *http.Request) {
	// Set before ServeContent, which would otherwise have to sniff the type.
	w.Header().Set("Content-Type", "image/png")
	// The mark cannot change within a build, so a client may keep it without asking.
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("ETag", productLogoETag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// The zero time suppresses Last-Modified, which would otherwise invite a client to
	// reason about the binary's build as though it were a file timestamp.
	http.ServeContent(w, r, "gedefense-logo.png", time.Time{}, bytes.NewReader(productLogo))
}
