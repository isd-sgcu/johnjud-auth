package token

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/service/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/repository/cache"
	jwtSvc "github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

type Service interface {
	CreateCredential(userId string, role constant.Role, authSessionId string) (*authProto.Credential, error)
	Validate(token string) (*tokenDto.UserCredential, error)
	CreateRefreshToken() string
	RemoveTokenCache(refreshToken string) error
}

func NewService(jwtService jwtSvc.Service, accessTokenCache cache.Repository, refreshTokenCache cache.Repository, uuidUtil utils.IUuidUtil) Service {
	return token.NewService(jwtService, accessTokenCache, refreshTokenCache, uuidUtil)
}
