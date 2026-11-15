// testissuer is a throwaway OIDC issuer for integration tests: it serves a
// discovery document and JWKS on -addr and writes a signed token for -sub /
// -aud to -out, then serves until killed. Not for production use.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5556", "listen address")
	sub := flag.String("sub", "", "token subject")
	aud := flag.String("aud", "", "token audience")
	out := flag.String("out", "token", "file to write the token to")
	flag.Parse()

	issuer := "http://" + *addr
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "test"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuer,
		Subject:  *sub,
		Audience: jwt.Audience{*aud},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
	}).Serialize()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, []byte(token), 0o600); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), KeyID: "test", Algorithm: string(jose.RS256), Use: "sig",
		}}})
	})
	log.Fatal(http.ListenAndServe(*addr, mux))
}
