// Copyright (c) 2021, salesforce.com, inc.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// For full license text, see the LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// testIssuer is an in-process OIDC issuer: it serves a discovery document and
// JWKS for signingKey, and mints tokens with it.
type testIssuer struct {
	t          *testing.T
	srv        *httptest.Server
	signingKey *rsa.PrivateKey
	// discoveryIssuer overrides the issuer advertised in the discovery doc.
	discoveryIssuer string
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	ti := &testIssuer{t: t, signingKey: mustKey(t)}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := ti.URL()
		if ti.discoveryIssuer != "" {
			iss = ti.discoveryIssuer
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss,
			"jwks_uri":                              ti.URL() + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: ti.signingKey.Public(), KeyID: "test-key", Algorithm: string(jose.RS256), Use: "sig",
		}}})
	})
	ti.srv = httptest.NewServer(mux)
	t.Cleanup(ti.srv.Close)
	return ti
}

func (ti *testIssuer) URL() string { return ti.srv.URL }

// token signs claims with key (the issuer's own key when nil).
func (ti *testIssuer) token(key *rsa.PrivateKey, std jwt.Claims, extra map[string]any) string {
	ti.t.Helper()
	if key == nil {
		key = ti.signingKey
	}
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "test-key"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		ti.t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(std).Claims(extra).Serialize()
	if err != nil {
		ti.t.Fatal(err)
	}
	return raw
}

func mustKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAuthenticate(t *testing.T) {
	ti := newTestIssuer(t)
	now := time.Now()
	valid := func(sub string) jwt.Claims {
		return jwt.Claims{
			Issuer:   ti.URL(),
			Subject:  sub,
			Audience: jwt.Audience{"mariadb"},
			Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(now),
		}
	}
	const k8sTemplate = `{{.Subject | trimPrefix "system:serviceaccount:"}}`

	cases := []struct {
		name             string
		user             string
		token            string
		userTemplate     string
		groupsClaimKey   string
		authorizedGroups []string
		requireACRs      []string
		notBefore        time.Time
		wantErr          string
	}{
		{
			name:  "valid user, valid token",
			user:  "jdoe",
			token: ti.token(nil, valid("jdoe"), nil),
		},
		{
			name:         "kubernetes serviceaccount subject maps to ns:name",
			user:         "apps:billing",
			token:        ti.token(nil, valid("system:serviceaccount:apps:billing"), nil),
			userTemplate: k8sTemplate,
		},
		{
			name:         "serviceaccount from another namespace is rejected",
			user:         "apps:billing",
			token:        ti.token(nil, valid("system:serviceaccount:other:billing"), nil),
			userTemplate: k8sTemplate,
			wantErr:      `expected user "other:billing" but is authenticating as "apps:billing"`,
		},
		{
			name:    "user does not match subject",
			user:    "jdoe",
			token:   ti.token(nil, valid("someone-else"), nil),
			wantErr: "expected user",
		},
		{
			name: "wrong audience",
			user: "jdoe",
			token: ti.token(nil, func() jwt.Claims {
				c := valid("jdoe")
				c.Audience = jwt.Audience{"https://kubernetes.default.svc.cluster.local"}
				return c
			}(), nil),
			wantErr: "expected audience",
		},
		{
			name: "wrong issuer",
			user: "jdoe",
			token: ti.token(nil, func() jwt.Claims {
				c := valid("jdoe")
				c.Issuer = "https://evil.example.com"
				return c
			}(), nil),
			wantErr: "id token issued by a different provider",
		},
		{
			name: "expired token",
			user: "jdoe",
			token: ti.token(nil, func() jwt.Claims {
				c := valid("jdoe")
				c.Expiry = jwt.NewNumericDate(now.Add(-time.Minute))
				return c
			}(), nil),
			wantErr: "token is expired",
		},
		{
			name:    "signed by a key the issuer does not publish",
			user:    "jdoe",
			token:   ti.token(mustKey(t), valid("jdoe"), nil),
			wantErr: "failed to verify signature",
		},
		{
			name:    "not a JWT",
			user:    "jdoe",
			token:   "hunter2",
			wantErr: "malformed jwt",
		},
		{
			name:             "authorized group present",
			user:             "jdoe",
			token:            ti.token(nil, valid("jdoe"), map[string]any{"groups": []string{"a", "dba"}}),
			authorizedGroups: []string{"dba"},
		},
		{
			name:             "authorized group missing",
			user:             "jdoe",
			token:            ti.token(nil, valid("jdoe"), map[string]any{"groups": []string{"a"}}),
			authorizedGroups: []string{"dba"},
			wantErr:          "but one of [dba] is required",
		},
		{
			name:             "no groups claim",
			user:             "jdoe",
			token:            ti.token(nil, valid("jdoe"), nil),
			authorizedGroups: []string{"dba"},
			wantErr:          "user is not member of any groups",
		},
		{
			name:             "custom groups claim key",
			user:             "jdoe",
			token:            ti.token(nil, valid("jdoe"), map[string]any{"roles": []string{"dba"}}),
			groupsClaimKey:   "roles",
			authorizedGroups: []string{"dba"},
		},
		{
			name:        "required acr present",
			user:        "jdoe",
			token:       ti.token(nil, valid("jdoe"), map[string]any{"acr": "mfa"}),
			requireACRs: []string{"pwd", "mfa"},
		},
		{
			name:      "issued after not_before",
			user:      "jdoe",
			token:     ti.token(nil, valid("jdoe"), nil),
			notBefore: now.Add(-time.Hour),
		},
		{
			name: "issued before not_before is revoked",
			user: "jdoe",
			token: ti.token(nil, func() jwt.Claims {
				c := valid("jdoe")
				c.IssuedAt = jwt.NewNumericDate(now.Add(-2 * time.Hour))
				return c
			}(), nil),
			notBefore: now.Add(-time.Hour),
			wantErr:   "before not_before",
		},
		{
			name: "no iat is rejected when not_before is set",
			user: "jdoe",
			token: ti.token(nil, func() jwt.Claims {
				c := valid("jdoe")
				c.IssuedAt = nil
				return c
			}(), nil),
			notBefore: now.Add(-time.Hour),
			wantErr:   "no iat claim",
		},
		{
			name: "no iat is fine without not_before",
			user: "jdoe",
			token: ti.token(nil, func() jwt.Claims {
				c := valid("jdoe")
				c.IssuedAt = nil
				return c
			}(), nil),
		},
		{
			name:        "required acr missing",
			user:        "jdoe",
			token:       ti.token(nil, valid("jdoe"), map[string]any{"acr": "pwd"}),
			requireACRs: []string{"mfa"},
			wantErr:     `acr is "pwd", but one of [mfa] is required`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			auth, err := discoverAuthenticator(ctx, ti.URL(), "mariadb", "")
			if err != nil {
				t.Fatal(err)
			}
			auth.UserTemplate = tc.userTemplate
			auth.GroupsClaimKey = tc.groupsClaimKey
			auth.AuthorizedGroups = tc.authorizedGroups
			auth.RequireACRs = tc.requireACRs
			auth.NotBefore = tc.notBefore

			err = auth.Authenticate(ctx, tc.user, tc.token)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("want success, got %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want error containing %q, got success", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDiscoveryIssuerMismatch(t *testing.T) {
	ti := newTestIssuer(t)
	ti.discoveryIssuer = "https://impostor.example.com"
	if _, err := discoverAuthenticator(context.Background(), ti.URL(), "mariadb", ""); err == nil {
		t.Fatal("want error when the discovery document advertises a different issuer")
	}
}
