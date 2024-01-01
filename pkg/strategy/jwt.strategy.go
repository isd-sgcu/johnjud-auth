package strategy

import (
	"github.com/golang-jwt/jwt/v4"
)

type JwtStrategy interface {
	AuthDecode(token *jwt.Token) (interface{}, error)
}
