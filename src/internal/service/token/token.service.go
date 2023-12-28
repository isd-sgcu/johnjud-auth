package token

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/repository/cache"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"time"
)

type serviceImpl struct {
	jwtService        jwt.Service
	accessTokenCache  cache.Repository
	refreshTokenCache cache.Repository
	uuidUtil          utils.IUuidUtil
}

func NewService(jwtService jwt.Service, accessTokenCache cache.Repository, refreshTokenCache cache.Repository, uuidUtil utils.IUuidUtil) *serviceImpl {
	return &serviceImpl{
		jwtService:        jwtService,
		accessTokenCache:  accessTokenCache,
		refreshTokenCache: refreshTokenCache,
		uuidUtil:          uuidUtil,
	}
}

func (s *serviceImpl) CreateCredential(userId string, role constant.Role) (*authProto.Credential, error) {
	accessToken, err := s.jwtService.SignAuth(userId, role)
	if err != nil {
		return nil, err
	}

	credential := &authProto.Credential{
		AccessToken:  accessToken,
		RefreshToken: s.CreateRefreshToken(),
		ExpiresIn:    int32(s.jwtService.GetConfig().ExpiresIn),
	}

	return credential, nil
}

func (s *serviceImpl) Validate(token string) (*tokenDto.UserCredential, error) {
	// verifyAuth -> jwt.Token
	jwtToken, err := s.jwtService.VerifyAuth(token)
	if err != nil {
		return nil, err
	}

	payloads := jwtToken.Claims.(tokenDto.AuthPayload)
	if payloads.Issuer != s.jwtService.GetConfig().Issuer {
		return nil, errors.New("invalid token")
	}

	if time.Unix(payloads.ExpiresAt.Unix(), 0).Before(time.Now()) {
		return nil, errors.New("expired token")
	}

	userCredential := &tokenDto.UserCredential{
		UserId: payloads.UserId,
		Role:   payloads.Role,
	}
	return userCredential, nil
}

func (s *serviceImpl) CreateRefreshToken() string {
	return s.uuidUtil.GetNewUUID().String()
}
