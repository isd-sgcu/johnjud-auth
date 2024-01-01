package jwt

import (
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/cfgldr"
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
)

type Service interface {
	SignAuth(userId string, role constant.Role, authSessionId string) (string, error)
	VerifyAuth(token string) (*_jwt.Token, error)
	GetConfig() *cfgldr.Jwt
}
