package jwt

import (
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/src/internal/service/jwt"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/strategy"
)

type Service interface {
	SignAuth(userId string, role constant.Role) (string, error)
	VerifyAuth(token string) (*_jwt.Token, error)
	GetConfig() *config.Jwt
}

func NewService(config config.Jwt, strategy strategy.JwtStrategy, jwtUtil utils.IJwtUtil) Service {
	return jwt.NewService(config, strategy, jwtUtil)
}
