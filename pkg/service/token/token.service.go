package token

import (
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/internal/domain/dto/token"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

type Service interface {
	CreateCredential(userId string, role constant.Role, authSessionId string) (*authProto.Credential, error)
	Validate(token string) (*tokenDto.UserCredential, error)
	CreateRefreshToken() string
	RemoveAccessTokenCache(authSessionId string) error
	FindRefreshTokenCache(refreshToken string) (*tokenDto.RefreshTokenCache, error)
	RemoveRefreshTokenCache(refreshToken string) error
}
