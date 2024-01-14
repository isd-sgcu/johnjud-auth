package token

import (
	"time"

	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/cache"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/jwt"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/token"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serviceImpl struct {
	jwtService              jwt.Service
	accessTokenCache        cache.Repository
	refreshTokenCache       cache.Repository
	resetPasswordTokenCache cache.Repository
	uuidUtil                utils.IUuidUtil
}

func NewService(jwtService jwt.Service, accessTokenCache cache.Repository, refreshTokenCache cache.Repository, resetPasswordTokenCache cache.Repository, uuidUtil utils.IUuidUtil) token.Service {
	return &serviceImpl{
		jwtService:              jwtService,
		accessTokenCache:        accessTokenCache,
		refreshTokenCache:       refreshTokenCache,
		resetPasswordTokenCache: resetPasswordTokenCache,
		uuidUtil:                uuidUtil,
	}
}

func (s *serviceImpl) CreateCredential(userId string, role constant.Role, authSessionId string) (*authProto.Credential, error) {
	accessToken, err := s.jwtService.SignAuth(userId, role, authSessionId)
	if err != nil {
		log.Error().
			Err(err).
			Str("service", "token").
			Str("module", "CreateCredential").
			Msg("Error signing jwt access token")
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
		log.Error().
			Err(err).
			Str("service", "token").
			Str("module", "CreateCredential").
			Msg("Error setting value to access token cache")
		return nil, err
	}

	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: authSessionId,
		UserID:        userId,
		Role:          role,
	}
	err = s.refreshTokenCache.SetValue(refreshToken, refreshTokenCache, jwtConf.RefreshTokenTTL)
	if err != nil {
		log.Error().
			Err(err).
			Str("service", "token").
			Str("module", "CreateCredential").
			Msg("Error setting value to refresh token cache")
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

func (s *serviceImpl) RemoveAccessTokenCache(authSessionId string) error {
	err := s.accessTokenCache.DeleteValue(authSessionId)
	if err != nil {
		if err != redis.Nil {
			return err
		}
	}

	return nil
}

func (s *serviceImpl) FindRefreshTokenCache(refreshToken string) (*tokenDto.RefreshTokenCache, error) {
	refreshTokenCache := &tokenDto.RefreshTokenCache{}
	err := s.refreshTokenCache.GetValue(refreshToken, refreshTokenCache)
	if err != nil {
		log.Error().
			Err(err).
			Str("service", "token").
			Str("module", "FindRefreshTokenCache").
			Msg("Error getting value from redis")
		if err != redis.Nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return refreshTokenCache, nil
}

func (s *serviceImpl) RemoveRefreshTokenCache(refreshToken string) error {
	err := s.refreshTokenCache.DeleteValue(refreshToken)
	if err != nil {
		if err != redis.Nil {
			return err
		}
	}

	return nil
}

func (s *serviceImpl) CreateResetPasswordToken(userId string) (string, error) {
	resetPasswordToken := s.CreateRefreshToken()
	tokenCache := &tokenDto.ResetPasswordTokenCache{
		UserID: userId,
	}
	err := s.resetPasswordTokenCache.SetValue(resetPasswordToken, tokenCache, 900)
	if err != nil {
		return "", err
	}
	return resetPasswordToken, nil
}

func (s *serviceImpl) FindResetPasswordToken(token string) (*tokenDto.ResetPasswordTokenCache, error) {
	tokenCache := &tokenDto.ResetPasswordTokenCache{}
	err := s.resetPasswordTokenCache.GetValue(token, tokenCache)
	if err != nil {
		if err != redis.Nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return tokenCache, nil
}

func (s *serviceImpl) RemoveResetPasswordToken(token string) error {
	err := s.resetPasswordTokenCache.DeleteValue(token)
	if err != nil {
		if err != redis.Nil {
			return err
		}
	}

	return nil
}
