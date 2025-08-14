package cadwallader

import (
	"context"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type jwkData struct {
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

type jwks struct {
	Keys []jwkData `json:"keys"`
}

// verify
func Verify(address string, token string) (user *User, err error) {
	jwkCache, err := jwk.NewCache(context.Background(), httprc.NewClient())
	if err != nil {
		return
	}

	if err = jwkCache.Register(context.Background(), address); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keyset, err := jwkCache.Refresh(ctx, address)
	if err != nil {
		return
	}

	verified, err := jwt.ParseString(token, jwt.WithKeySet(keyset))
	if err != nil {
		return
	}

	user = new(User)
	if err := verified.Get("user_id", &user.ID); err != nil {
		return nil, err
	}
	if err := verified.Get("username", &user.Name); err != nil {
		return nil, err
	}
	if err := verified.Get("email", &user.Email); err != nil {
		return nil, err
	}
	if err := verified.Get("avatar", &user.Avatar); err != nil {
		return nil, err
	}

	return user, nil
}
