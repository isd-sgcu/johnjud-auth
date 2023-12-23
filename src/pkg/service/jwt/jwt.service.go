package jwt

import (
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/service/jwt"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/strategy"
)

type Service interface {
	SignAuth(userId string) (string, error)
	VerifyAuth(token string) (*_jwt.Token, error)
	GetConfig() *config.Jwt
}

func NewService(config config.Jwt, strategy strategy.JwtStrategy) Service {
	return jwt.NewService(config, strategy)
}