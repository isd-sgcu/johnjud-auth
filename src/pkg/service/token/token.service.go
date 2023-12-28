package token

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/service/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	jwtSvc "github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

type Service interface {
	CreateCredential(userId string, role constant.Role) (*authProto.Credential, error)
	Validate(token string) (*tokenDto.UserCredential, error)
	CreateRefreshToken() string
}

func NewService(jwtService jwtSvc.Service, uuidUtil utils.IUuidUtil) Service {
	return token.NewService(jwtService, uuidUtil)
}
