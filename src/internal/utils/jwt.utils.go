package utils

import (
	"github.com/golang-jwt/jwt/v4"
	"time"
)

type IJwtUtil interface {
	GenerateJwtToken(method jwt.SigningMethod, payloads jwt.Claims) *jwt.Token
	GetNumericDate(time time.Time) *jwt.NumericDate
	SignedTokenString(token *jwt.Token, secret string) (string, error)
	ParseToken(tokenStr string, keyFunc jwt.Keyfunc) (*jwt.Token, error)
}

type JwtUtil struct{}

func (u *JwtUtil) GenerateJwtToken(method jwt.SigningMethod, payloads jwt.Claims) *jwt.Token {
	return jwt.NewWithClaims(method, payloads)
}

func (u *JwtUtil) GetNumericDate(time time.Time) *jwt.NumericDate {
	return jwt.NewNumericDate(time)
}

func (u *JwtUtil) SignedTokenString(token *jwt.Token, secret string) (string, error) {
	return token.SignedString([]byte(secret))
}

func (u *JwtUtil) ParseToken(tokenStr string, keyFunc jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, keyFunc)
}
