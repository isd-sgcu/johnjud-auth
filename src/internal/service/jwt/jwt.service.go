package jwt

import (
	"fmt"
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/strategy"
	"github.com/pkg/errors"
	"time"
)

type serviceImpl struct {
	config   config.Jwt
	strategy strategy.JwtStrategy
	jwtUtil  utils.IJwtUtil
}

func NewService(config config.Jwt, strategy strategy.JwtStrategy, jwtUtil utils.IJwtUtil) *serviceImpl {
	return &serviceImpl{config: config, strategy: strategy, jwtUtil: jwtUtil}
}

func (s *serviceImpl) SignAuth(userId string) (string, error) {
	payloads := tokenDto.AuthPayload{
		RegisteredClaims: _jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			ExpiresAt: s.jwtUtil.GetNumericDate(time.Now().Add(time.Second * time.Duration(s.config.ExpiresIn))),
			IssuedAt:  s.jwtUtil.GetNumericDate(time.Now()),
		},
		UserId: userId,
	}

	token := s.jwtUtil.GenerateJwtToken(_jwt.SigningMethodHS256, payloads)

	tokenStr, err := s.jwtUtil.SignedTokenString(token, s.config.Secret)
	if err != nil {
		return "", errors.New(fmt.Sprintf("Error while signing the token due to: %s", err.Error()))
	}

	return tokenStr, nil
}

func (s *serviceImpl) VerifyAuth(token string) (*_jwt.Token, error) {
	return s.jwtUtil.ParseToken(token, s.strategy.AuthDecode)
}

func (s *serviceImpl) GetConfig() *config.Jwt {
	return nil
}
