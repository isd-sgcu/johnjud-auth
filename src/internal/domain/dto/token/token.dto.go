package token

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
)

type UserCredential struct {
	UserId string        `json:"user_id"`
	Role   constant.Role `json:"role"`
}

type AuthPayload struct {
	jwt.RegisteredClaims
	UserId string        `json:"user_id"`
	Role   constant.Role `json:"role"`
}
