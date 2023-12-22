package jwt

import (
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/strategy"
)

type serviceImpl struct {
	config   config.Jwt
	strategy strategy.JwtStrategy
}

func NewService(confif config.Jwt, strategy strategy.JwtStrategy) *serviceImpl {
	return &serviceImpl{config: confif, strategy: strategy}
}

func (s *serviceImpl) SignAuth(userId string) (string, error) {
	return "", nil
}

func (s *serviceImpl) VerifyAuth(token string) (*_jwt.Token, error) {
	return nil, nil
}

func (s *serviceImpl) GetConfig() *config.Jwt {
	return nil
}
