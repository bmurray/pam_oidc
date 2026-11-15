// Copyright (c) 2021, salesforce.com, inc.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// For full license text, see the LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type config struct {
	// Issuer is the OpenID Connect issuer
	Issuer string
	// Aud is the expected aud(ience) value for valid OIDC tokens
	Aud string
	// UserTemplate is a template that, when rendered with the JWT claims, should
	// match the user being authenticated.
	UserTemplate string
	// GroupsClaimKey is the name of the key within the token claims that
	// specifies which groups a user is a member of.
	GroupsClaimKey string
	// AuthorizedGroups is a list of groups required for authentication to pass.
	// A user must be a member of at least one of the groups in the list, if
	// specified.
	AuthorizedGroups []string
	// RequireACRs is a list of required ACRs required for authentication to pass.
	// one of the acr values must be present in the claims.
	RequireACRs []string
	// HTTPProxy is the HTTP proxy server used to connect to HTTP services.
	HTTPProxy string
	// NotBefore, if set, rejects tokens issued (by their iat claim) before this
	// time, revoking every token minted earlier at once.
	NotBefore time.Time
}

func configFromArgs(args []string) (*config, error) {
	c := &config{}

	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return nil, fmt.Errorf("malformed arg: %v", arg)
		}

		switch key {
		case "issuer":
			c.Issuer = value
		case "aud":
			c.Aud = value
		case "user_template":
			c.UserTemplate = value
		case "groups_claim_key":
			c.GroupsClaimKey = value
		case "authorized_groups":
			c.AuthorizedGroups = strings.Split(value, ",")
		case "require_acr":
			c.RequireACRs = []string{value}
		case "require_acrs":
			c.RequireACRs = strings.Split(value, ",")
		case "http_proxy":
			c.HTTPProxy = value
		case "not_before":
			t, err := parseTime(value)
			if err != nil {
				return nil, fmt.Errorf("not_before: %w", err)
			}
			c.NotBefore = t
		default:
			return nil, fmt.Errorf("unknown option: %v", key)
		}
	}

	return c, nil
}

// parseTime accepts an RFC 3339 timestamp or Unix seconds.
func parseTime(s string) (time.Time, error) {
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(secs, 0), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("want an RFC 3339 timestamp or Unix seconds, got %q", s)
	}
	return t, nil
}
