package cadwallader

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/go-resty/resty/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var pubkey *rsa.PublicKey

type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type User struct {
	ID     string
	Name   string
	Email  string
	Avatar string
}

func Init(address string) error {
	client := resty.New()
	res, err := client.R().Get(address + "/jwks")
	if err != nil {
		return err
	}

	jwk := new(jwk)
	if err := json.Unmarshal(res.Body(), jwk); err != nil {
		return err
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return err
	}

	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	pubkey = &rsa.PublicKey{
		N: n,
		E: e,
	}

	return nil
}

func Verify(token string, expectedAud string) (*User, error) {
	verified, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.RS256(), pubkey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse/verify JWT: %w", err)
	}

	user := new(User)
	claims := map[string]any{"user_id": user.ID, "username": user.Name, "email": user.Email, "avatar": user.Avatar}
	for key, claim := range claims {
		if err := verified.Get(key, claim); err != nil {
			return nil, err
		}
	}

	return user, nil
}
