package jwt

import (
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/cfgldr"
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/internal/service/jwt"
	"github.com/isd-sgcu/johnjud-auth/internal/utils"
	jwtStg "github.com/isd-sgcu/johnjud-auth/pkg/strategy"
)

type Service interface {
	SignAuth(userId string, role constant.Role, authSessionId string) (string, error)
	VerifyAuth(token string) (*_jwt.Token, error)
	GetConfig() *cfgldr.Jwt
}

func NewService(config cfgldr.Jwt, strategy jwtStg.JwtStrategy, jwtUtil utils.IJwtUtil) Service {
	return jwt.NewService(config, strategy, jwtUtil)
}
