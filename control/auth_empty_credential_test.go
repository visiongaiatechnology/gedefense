// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAnEmptyCredentialNeverAuthenticates is the permanent guard for a bypass that a token-rotation
// design would have opened: tokenEqual compares digests, and the digest of the empty string equals
// itself - so a request *without* an Authorization header would authenticate the moment the expected
// token became empty. An empty expected token is exactly what an unreadable or just-replaced token
// file produces, which is the moment a rotation happens.
//
// The guard therefore rejects an empty credential before any comparison, whatever the expected value
// is. This test exists because the naive version of the rotation feature would have been green.
func TestAnEmptyCredentialNeverAuthenticates(t *testing.T) {
	cases := []struct {
		name  string
		token string
		auth  string
		want  int
	}{
		{"no header, empty expected token", "", "", http.StatusUnauthorized},
		{"empty bearer, empty expected token", "", "Bearer ", http.StatusUnauthorized},
		{"wrong credential, empty expected token", "", "Bearer something", http.StatusUnauthorized},
		{"no header, real expected token", "expected-token-value", "", http.StatusUnauthorized},
		{"empty bearer, real expected token", "expected-token-value", "Bearer ", http.StatusUnauthorized},
		{"correct credential", "expected-token-value", "Bearer expected-token-value", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &APIServer{token: tc.token}
			reached := false
			handler := server.auth(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			handler(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if wantReached := tc.want == http.StatusOK; reached != wantReached {
				t.Fatalf("handler reached = %t, want %t", reached, wantReached)
			}
		})
	}
}
