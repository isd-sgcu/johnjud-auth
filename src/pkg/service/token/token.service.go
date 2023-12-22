package token

import (
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/service/token"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

type Service interface {
	CreateCredential(userId string, secret string) (*authProto.Credential, error)
	Validate(token string) (*tokenDto.UserCredential, error)
}

func NewService(jwtService jwt.Service) Service {
	return token.NewService(jwtService)
}
