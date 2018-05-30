package auth

import (
	"time"

	"github.com/auth0/go-jwt-middleware"

	jwt "github.com/dgrijalva/jwt-go"
)

// Claim struct wraps jwt.StandardClaim and add user name data
type Claim struct {
	User string `json:"user"`
	jwt.StandardClaims
}

// Tokenizer prepare a token producing function for this issuer / jwtKey configuration
func Tokenizer(issuer, jwtKey string) func(string) (string, error) {
	return func(username string) (string, error) {
		claim := Claim{
			username,
			jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
				Issuer:    issuer,
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
		return token.SignedString([]byte(jwtKey))
	}
}

// TokenMiddleware produces a JWTMiddleware using `jwtKey` string
func TokenMiddleware(jwtKey string) *jwtmiddleware.JWTMiddleware {
	return jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtKey), nil
		},
		SigningMethod: jwt.SigningMethodHS256,
	})
}
