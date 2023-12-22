package token

import "github.com/isd-sgcu/johnjud-auth/src/internal/constant"

type UserCredential struct {
	UserId string        `json:"user_id"`
	Role   constant.Role `json:"role"`
}
