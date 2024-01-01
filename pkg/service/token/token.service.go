package token

import (
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/internal/service/token"
	"github.com/isd-sgcu/johnjud-auth/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/cache"
	jwtSvc "github.com/isd-sgcu/johnjud-auth/pkg/service/jwt"
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
