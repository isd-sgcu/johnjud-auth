package token

import (
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/cache"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/jwt"
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
		Role:         role,
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

	payloads := jwtToken.Claims.(_jwt.MapClaims)
	if payloads["iss"] != s.jwtService.GetConfig().Issuer {
		return nil, errors.New("invalid token")
	}

	if time.Unix(int64(payloads["exp"].(float64)), 0).Before(time.Now()) {
		return nil, errors.New("expired token")
	}

	accessTokenCache := &tokenDto.AccessTokenCache{}
	err = s.accessTokenCache.GetValue(payloads["auth_session_id"].(string), accessTokenCache)
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
		UserID:        payloads["user_id"].(string),
		Role:          accessTokenCache.Role,
		AuthSessionID: payloads["auth_session_id"].(string),
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
