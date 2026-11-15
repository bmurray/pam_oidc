// Copyright (c) 2021, salesforce.com, inc.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// For full license text, see the LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"text/template"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/http/httpproxy"
)

type authenticator struct {
	// UserTemplate is a template that, when rendered with the JWT claims, should
	// match the user being authenticated.
	//
	// `{{.Subject}}` is used by default if not set.
	UserTemplate string

	// GroupsClaimKey is the name of the key within the token claims that
	// specifies which groups a user is a member of.
	//
	// `groups` is used by default if not set.
	GroupsClaimKey string

	// AuthorizedGroups is a list of groups required for authentication to pass.
	// A user must be a member of at least one of the groups in the list, if
	// specified.
	//
	// If the list is empty, group membership is not required for authentication
	// to pass.
	AuthorizedGroups []string

	// RequireACRs is a list of required values of the acr claim in the token for
	// authentication to pass. At least one of the acrs must be present if specified
	//
	// If the list is empty, the ACR value is not checked.
	RequireACRs []string

	verifier *oidc.IDTokenVerifier
}

// claims is what user templates render against. Field names match the
// original pardot/oidc Claims type so existing templates keep working.
type claims struct {
	Subject string
	ACR     string
	Extra   map[string]any
}

func httpClient(httpProxy string) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if httpProxy != "" {
		// Use no_proxy from environment, if present, but override proxy URL
		cfg := httpproxy.FromEnvironment()
		cfg.HTTPProxy = httpProxy
		cfg.HTTPSProxy = httpProxy

		proxyFunc := cfg.ProxyFunc()
		transport.Proxy = func(r *http.Request) (*url.URL, error) {
			return proxyFunc(r.URL)
		}
	}
	return &http.Client{Transport: transport}
}

func discoverAuthenticator(ctx context.Context, issuer string, aud string, httpProxy string) (*authenticator, error) {
	// The client is attached to the context so go-oidc uses it for both the
	// discovery document and the JWKS fetches.
	ctx = oidc.ClientContext(ctx, httpClient(httpProxy))

	// NewProvider rejects a discovery document whose issuer differs from the
	// configured one, so a token can't be verified against the wrong issuer.
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discovering verifier: %w", err)
	}

	// ClientID is the required audience: the verifier rejects tokens whose aud
	// does not contain it, and checks issuer, expiry and signature.
	return &authenticator{
		verifier: provider.Verifier(&oidc.Config{ClientID: aud}),
	}, nil
}

// Authenticate authenticates a user with the provided token.
func (a *authenticator) Authenticate(ctx context.Context, user string, token string) error {
	idToken, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return fmt.Errorf("verifying token: %w", err)
	}

	c := claims{Subject: idToken.Subject}
	if err := idToken.Claims(&c.Extra); err != nil {
		return fmt.Errorf("decoding claims: %w", err)
	}
	if acr, ok := c.Extra["acr"].(string); ok {
		c.ACR = acr
	}

	userTemplate := "{{.Subject}}"
	if a.UserTemplate != "" {
		userTemplate = a.UserTemplate
	}

	userTmpl, err := template.New("").Funcs(template.FuncMap{
		"trimPrefix": func(prefix, s string) string { return strings.TrimPrefix(s, prefix) },
		"trimSuffix": func(suffix, s string) string { return strings.TrimSuffix(s, suffix) },
	}).Parse(userTemplate)
	if err != nil {
		return fmt.Errorf("parsing user template: %w", err)
	}

	buf := new(bytes.Buffer)
	if err := userTmpl.Execute(buf, c); err != nil {
		return fmt.Errorf("executing user template: %w", err)
	}

	wantUser := buf.String()
	if wantUser != user {
		return fmt.Errorf("expected user %q but is authenticating as %q", wantUser, user)
	}

	// Validate AuthorizedGroups / GroupClaimsKey
	if len(a.AuthorizedGroups) > 0 {
		groupsClaimKey := "groups"
		if len(a.GroupsClaimKey) > 0 {
			groupsClaimKey = a.GroupsClaimKey
		}

		groupsClaim, ok := c.Extra[groupsClaimKey].([]any)
		if !ok {
			return fmt.Errorf("user is not member of any groups, but one of %v is required", a.AuthorizedGroups)
		}

		groups := make([]string, 0, len(groupsClaim))
		for _, groupVal := range groupsClaim {
			if group, ok := groupVal.(string); ok {
				groups = append(groups, group)
			}
		}
		if !isMemberOfAtLeastOneGroup(a.AuthorizedGroups, groups) {
			return fmt.Errorf("user is member of %v, but one of %v is required", groups, a.AuthorizedGroups)
		}
	}

	// Validate RequireACRs
	if len(a.RequireACRs) > 0 {
		if !slices.Contains(a.RequireACRs, c.ACR) {
			return fmt.Errorf("acr is %q, but one of %v is required", c.ACR, a.RequireACRs)
		}
	}

	return nil
}

func isMemberOfAtLeastOneGroup(authorizedGroups []string, groups []string) bool {
	for _, wantGroup := range authorizedGroups {
		if slices.Contains(groups, wantGroup) {
			return true
		}
	}
	return false
}
