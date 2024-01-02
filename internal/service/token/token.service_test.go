package token

import (
	"github.com/go-faker/faker/v4"
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/isd-sgcu/johnjud-auth/cfgldr"
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/mocks/repository/cache"
	"github.com/isd-sgcu/johnjud-auth/mocks/service/jwt"
	"github.com/isd-sgcu/johnjud-auth/mocks/utils"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
	"time"
)

type TokenServiceTest struct {
	suite.Suite
	userId        string
	role          constant.Role
	authSessionId string
	accessToken   string
	refreshToken  *uuid.UUID
	jwtConfig     *cfgldr.Jwt
	validateToken string
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(TokenServiceTest))
}

func (t *TokenServiceTest) SetupTest() {
	userId := faker.UUIDDigit()
	role := constant.USER
	authSessionId := faker.UUIDDigit()
	accessToken := "testAccessToken"
	refreshToken := uuid.New()
	jwtConfig := &cfgldr.Jwt{
		Secret:          "testSecret",
		ExpiresIn:       3600,
		RefreshTokenTTL: 604800,
		Issuer:          "testIssuer",
	}
	validateToken := ""

	t.userId = userId
	t.role = role
	t.authSessionId = authSessionId
	t.accessToken = accessToken
	t.refreshToken = &refreshToken
	t.jwtConfig = jwtConfig
	t.validateToken = validateToken
}

func (t *TokenServiceTest) TestCreateCredentialSuccess() {
	accessTokenCache := &tokenDto.AccessTokenCache{
		Token:        t.accessToken,
		Role:         t.role,
		RefreshToken: t.refreshToken.String(),
	}
	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: t.authSessionId,
		UserID:        t.userId,
		Role:          t.role,
	}

	expected := authProto.Credential{
		AccessToken:  t.accessToken,
		RefreshToken: t.refreshToken.String(),
		ExpiresIn:    int32(t.jwtConfig.ExpiresIn),
	}

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("SignAuth", t.userId, t.role, t.authSessionId).Return(t.accessToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)
	uuidUtil.On("GetNewUUID").Return(t.refreshToken)
	accessTokenRepo.EXPECT().SetValue(t.authSessionId, accessTokenCache, t.jwtConfig.ExpiresIn).Return(nil)
	refreshTokenRepo.EXPECT().SetValue(t.refreshToken.String(), refreshTokenCache, t.jwtConfig.RefreshTokenTTL).Return(nil)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.CreateCredential(t.userId, t.role, t.authSessionId)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected.AccessToken, actual.AccessToken)
	assert.Equal(t.T(), expected.RefreshToken, actual.RefreshToken)
	assert.Equal(t.T(), expected.ExpiresIn, actual.ExpiresIn)
}

func (t *TokenServiceTest) TestCreateCredentialSignAuthFailed() {
	signAuthError := errors.New("Error while signing token")
	expected := errors.New("Error while signing token")

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("SignAuth", t.userId, t.role, t.authSessionId).Return("", signAuthError)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.CreateCredential(t.userId, t.role, t.authSessionId)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestCreateCredentialSetAccessTokenFailed() {
	accessTokenCache := &tokenDto.AccessTokenCache{
		Token:        t.accessToken,
		Role:         t.role,
		RefreshToken: t.refreshToken.String(),
	}
	setCacheErr := errors.New("Internal server error")
	expected := setCacheErr

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("SignAuth", t.userId, t.role, t.authSessionId).Return(t.accessToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)
	uuidUtil.On("GetNewUUID").Return(t.refreshToken)
	accessTokenRepo.EXPECT().SetValue(t.authSessionId, accessTokenCache, t.jwtConfig.ExpiresIn).Return(setCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.CreateCredential(t.userId, t.role, t.authSessionId)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestCreateCredentialSetRefreshTokenFailed() {
	accessTokenCache := &tokenDto.AccessTokenCache{
		Token:        t.accessToken,
		Role:         t.role,
		RefreshToken: t.refreshToken.String(),
	}
	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: t.authSessionId,
		UserID:        t.userId,
		Role:          t.role,
	}
	setCacheErr := errors.New("Internal server error")
	expected := setCacheErr

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("SignAuth", t.userId, t.role, t.authSessionId).Return(t.accessToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)
	uuidUtil.On("GetNewUUID").Return(t.refreshToken)
	accessTokenRepo.EXPECT().SetValue(t.authSessionId, accessTokenCache, t.jwtConfig.ExpiresIn).Return(nil)
	refreshTokenRepo.EXPECT().SetValue(t.refreshToken.String(), refreshTokenCache, t.jwtConfig.RefreshTokenTTL).Return(setCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.CreateCredential(t.userId, t.role, t.authSessionId)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestValidateSuccess() {
	expected := &tokenDto.UserCredential{
		UserID:        t.userId,
		Role:          "",
		AuthSessionID: t.authSessionId,
		RefreshToken:  "",
	}
	payloads := _jwt.MapClaims{
		"iss":             t.jwtConfig.Issuer,
		"exp":             float64(_jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(t.jwtConfig.ExpiresIn))).Unix()),
		"iat":             float64(_jwt.NewNumericDate(time.Now()).Unix()),
		"user_id":         t.userId,
		"auth_session_id": t.authSessionId,
	}
	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}
	accessTokenCache := &tokenDto.AccessTokenCache{}

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)
	accessTokenRepo.EXPECT().GetValue(payloads["auth_session_id"].(string), accessTokenCache).Return(nil)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), *expected, *actual)
}

func (t *TokenServiceTest) TestValidateInvalidIssuer() {
	expected := errors.New("invalid token")

	payloads := _jwt.MapClaims{
		"iss":             "invalid issuer",
		"exp":             float64(_jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(t.jwtConfig.ExpiresIn))).Unix()),
		"iat":             float64(_jwt.NewNumericDate(time.Now()).Unix()),
		"user_id":         t.userId,
		"auth_session_id": t.authSessionId,
	}

	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestValidateExpireToken() {
	expected := errors.New("expired token")

	payloads := _jwt.MapClaims{
		"iss":             t.jwtConfig.Issuer,
		"exp":             float64(_jwt.NewNumericDate(time.Now().Add(time.Second * (-time.Duration(t.jwtConfig.ExpiresIn)))).Unix()),
		"iat":             float64(_jwt.NewNumericDate(time.Now()).Unix()),
		"user_id":         t.userId,
		"auth_session_id": t.authSessionId,
	}
	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestValidateVerifyFailed() {
	expected := errors.New("invalid token")

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(nil, expected)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestValidateGetCacheKeyNotFound() {
	expected := errors.New("invalid token")

	payloads := _jwt.MapClaims{
		"iss":             t.jwtConfig.Issuer,
		"exp":             float64(_jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(t.jwtConfig.ExpiresIn))).Unix()),
		"iat":             float64(_jwt.NewNumericDate(time.Now()).Unix()),
		"user_id":         t.userId,
		"auth_session_id": t.authSessionId,
	}
	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}
	accessTokenCache := &tokenDto.AccessTokenCache{}

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)
	accessTokenRepo.EXPECT().GetValue(payloads["auth_session_id"].(string), accessTokenCache).Return(redis.Nil)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestValidateGetCacheInternalFailed() {
	payloads := _jwt.MapClaims{
		"iss":             t.jwtConfig.Issuer,
		"exp":             float64(_jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(t.jwtConfig.ExpiresIn))).Unix()),
		"iat":             float64(_jwt.NewNumericDate(time.Now()).Unix()),
		"user_id":         t.userId,
		"auth_session_id": t.authSessionId,
	}
	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}
	accessTokenCache := &tokenDto.AccessTokenCache{}
	getCacheErr := errors.New("internal server error")

	expected := getCacheErr

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)
	accessTokenRepo.EXPECT().GetValue(payloads["auth_session_id"].(string), accessTokenCache).Return(getCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestValidateInvalidToken() {
	invalidToken := faker.Word()
	expected := errors.New("invalid token")

	payloads := _jwt.MapClaims{
		"iss":             t.jwtConfig.Issuer,
		"exp":             float64(_jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(t.jwtConfig.ExpiresIn))).Unix()),
		"iat":             float64(_jwt.NewNumericDate(time.Now()).Unix()),
		"user_id":         t.userId,
		"auth_session_id": t.authSessionId,
	}
	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}
	accessTokenCache := &tokenDto.AccessTokenCache{}

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", invalidToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)
	accessTokenRepo.EXPECT().GetValue(payloads["auth_session_id"].(string), accessTokenCache).Return(nil)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.Validate(invalidToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *TokenServiceTest) TestCreateRefreshTokenSuccess() {
	expected := t.refreshToken.String()

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	uuidUtil.On("GetNewUUID").Return(t.refreshToken)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual := tokenSvc.CreateRefreshToken()

	assert.Equal(t.T(), expected, actual)
}

func (t *TokenServiceTest) TestFindRefreshTokenCacheSuccess() {
	expected := &tokenDto.RefreshTokenCache{}

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	refreshTokenRepo.EXPECT().GetValue(t.refreshToken.String(), &tokenDto.RefreshTokenCache{}).Return(nil)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.FindRefreshTokenCache(t.refreshToken.String())

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected, actual)
}

func (t *TokenServiceTest) TestFindRefreshTokenCacheInvalid() {
	getCacheErr := redis.Nil

	expected := status.Error(codes.InvalidArgument, getCacheErr.Error())

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	refreshTokenRepo.EXPECT().GetValue(t.refreshToken.String(), &tokenDto.RefreshTokenCache{}).Return(getCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.FindRefreshTokenCache(t.refreshToken.String())

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected, err)
}

func (t *TokenServiceTest) TestFindRefreshTokenCacheInternalError() {
	getCacheErr := errors.New("internal server error")

	expected := status.Error(codes.Internal, getCacheErr.Error())

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	refreshTokenRepo.EXPECT().GetValue(t.refreshToken.String(), &tokenDto.RefreshTokenCache{}).Return(getCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	actual, err := tokenSvc.FindRefreshTokenCache(t.refreshToken.String())

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected, err)
}

func (t *TokenServiceTest) TestRemoveTokenCacheSuccess() {
	refreshTokenCache := &tokenDto.RefreshTokenCache{}

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	refreshTokenRepo.EXPECT().GetValue(t.refreshToken.String(), refreshTokenCache).Return(nil)
	refreshTokenRepo.EXPECT().DeleteValue(t.refreshToken.String()).Return(nil)
	accessTokenRepo.EXPECT().DeleteValue(refreshTokenCache.AuthSessionID).Return(nil)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	err := tokenSvc.RemoveTokenCache(t.refreshToken.String())

	assert.Nil(t.T(), err)
}

func (t *TokenServiceTest) TestRemoveTokenCacheGetRefreshTokenNotFound() {
	refreshTokenCache := &tokenDto.RefreshTokenCache{}
	getRefreshTokenCacheErr := redis.Nil

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	refreshTokenRepo.EXPECT().GetValue(t.refreshToken.String(), refreshTokenCache).Return(getRefreshTokenCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	err := tokenSvc.RemoveTokenCache(t.refreshToken.String())

	assert.Nil(t.T(), err)
}

func (t *TokenServiceTest) TestRemoveTokenCacheGetRefreshTokenInternalFailed() {
	refreshTokenCache := &tokenDto.RefreshTokenCache{}
	getRefreshTokenCacheErr := errors.New("internal server error")

	expected := getRefreshTokenCacheErr

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	refreshTokenRepo.EXPECT().GetValue(t.refreshToken.String(), refreshTokenCache).Return(getRefreshTokenCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	err := tokenSvc.RemoveTokenCache(t.refreshToken.String())

	assert.Equal(t.T(), expected, err)
}

func (t *TokenServiceTest) TestRemoveTokenCacheDeleteRefreshTokenInternalFailed() {
	refreshTokenCache := &tokenDto.RefreshTokenCache{}
	deleteRefreshTokenCacheErr := errors.New("internal server error")

	expected := deleteRefreshTokenCacheErr

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	refreshTokenRepo.EXPECT().GetValue(t.refreshToken.String(), refreshTokenCache).Return(nil)
	refreshTokenRepo.EXPECT().DeleteValue(t.refreshToken.String()).Return(deleteRefreshTokenCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	err := tokenSvc.RemoveTokenCache(t.refreshToken.String())

	assert.Equal(t.T(), expected, err)
}

func (t *TokenServiceTest) TestRemoveTokenCacheDeleteAccessTokenInternalFailed() {
	refreshTokenCache := &tokenDto.RefreshTokenCache{}
	deleteAccessTokenCacheErr := errors.New("internal server error")

	expected := deleteAccessTokenCacheErr

	controller := gomock.NewController(t.T())

	jwtService := jwt.JwtServiceMock{}
	accessTokenRepo := mock_cache.NewMockRepository(controller)
	refreshTokenRepo := mock_cache.NewMockRepository(controller)
	uuidUtil := utils.UuidUtilMock{}

	refreshTokenRepo.EXPECT().GetValue(t.refreshToken.String(), refreshTokenCache).Return(nil)
	refreshTokenRepo.EXPECT().DeleteValue(t.refreshToken.String()).Return(nil)
	accessTokenRepo.EXPECT().DeleteValue(refreshTokenCache.AuthSessionID).Return(deleteAccessTokenCacheErr)

	tokenSvc := NewService(&jwtService, accessTokenRepo, refreshTokenRepo, &uuidUtil)
	err := tokenSvc.RemoveTokenCache(t.refreshToken.String())

	assert.Equal(t.T(), expected, err)
}
