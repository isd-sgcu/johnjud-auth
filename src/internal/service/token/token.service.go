package token

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/repository/cache"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
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

func (s *serviceImpl) CreateCredential(userId string, role constant.Role, authSessionId string) (*authProto.Credential, error) {
	accessToken, err := s.jwtService.SignAuth(userId, role, authSessionId)
	if err != nil {
		return nil, err
	}

	refreshToken := s.CreateRefreshToken()
	jwtConf := s.jwtService.GetConfig()

	accessTokenCache := &tokenDto.AccessTokenCache{
		Token:        accessToken,
		RefreshToken: refreshToken,
	}
	err = s.accessTokenCache.SetValue(authSessionId, accessTokenCache, jwtConf.ExpiresIn)
	if err != nil {
		return nil, err
	}

	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: authSessionId,
		UserID:        userId,
		Role:          role,
	}
	err = s.refreshTokenCache.SetValue(refreshToken, refreshTokenCache, jwtConf.RefreshTokenTTL)
	if err != nil {
		return nil, err
	}

	credential := &authProto.Credential{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int32(jwtConf.ExpiresIn),
	}

	return credential, nil
}

func (s *serviceImpl) Validate(token string) (*tokenDto.UserCredential, error) {
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

	accessTokenCache := &tokenDto.AccessTokenCache{}
	err = s.accessTokenCache.GetValue(payloads.AuthSessionID, accessTokenCache)
	if err != nil {
		if err != redis.Nil {
			return nil, err
		}
		return nil, errors.New("invalid token")
	}

	if token != accessTokenCache.Token {
		return nil, errors.New("invalid token")
	}

	userCredential := &tokenDto.UserCredential{
		UserID:        payloads.UserID,
		Role:          payloads.Role,
		AuthSessionID: payloads.AuthSessionID,
		RefreshToken:  accessTokenCache.RefreshToken,
	}
	return userCredential, nil
}

func (s *serviceImpl) CreateRefreshToken() string {
	return s.uuidUtil.GetNewUUID().String()
}

func (s *serviceImpl) RemoveTokenCache(refreshToken string) error {
	refreshTokenCache := &tokenDto.RefreshTokenCache{}
	err := s.refreshTokenCache.GetValue(refreshToken, refreshTokenCache)
	if err != nil {
		if err != redis.Nil {
			return err
		}
		return nil
	}

	err = s.refreshTokenCache.DeleteValue(refreshToken)
	if err != nil {
		if err != redis.Nil {
			return err
		}
	}

	err = s.accessTokenCache.DeleteValue(refreshTokenCache.AuthSessionID)
	if err != nil {
		if err != redis.Nil {
			return err
		}
	}

	return nil
}
