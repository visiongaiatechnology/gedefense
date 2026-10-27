package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"net/http"
	"time"
)

// The Entenprise mascot is part of the product's identity, so it travels in the
// gateway binary like the product mark. The login page must not depend on an
// asset directory that does not exist on the target host.
//
//go:embed sirdu.png
var mascotImage []byte

var mascotETag = func() string {
	sum := sha256.Sum256(mascotImage)
	return `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`
}()

// mascot serves the embedded brand figure before authentication. It is a static
// image with no user-controlled path and discloses only the product's identity.
func (g *gateway) mascot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	w.Header().Set("ETag", mascotETag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, "sirdu.png", time.Time{}, bytes.NewReader(mascotImage))
}
