package token

import (
	"github.com/go-faker/faker/v4"
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	mock_cache "github.com/isd-sgcu/johnjud-auth/src/mocks/repository/cache"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/service/jwt"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/utils"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
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
	jwtConfig     *config.Jwt
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
	jwtConfig := &config.Jwt{
		Secret:          "testSecret",
		ExpiresIn:       3600,
		RefreshTokenTTL: 604800,
		Issuer:          "testIssuer",
	}
	validateToken := "testValidateToken"

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
		RefreshToken: t.refreshToken.String(),
	}
	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: t.authSessionId,
		UserId:        t.userId,
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
		RefreshToken: t.refreshToken.String(),
	}
	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: t.authSessionId,
		UserId:        t.userId,
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
		UserId: t.userId,
		Role:   constant.USER,
	}

	payloads := tokenDto.AuthPayload{
		RegisteredClaims: _jwt.RegisteredClaims{
			Issuer:    t.jwtConfig.Issuer,
			ExpiresAt: _jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(t.jwtConfig.ExpiresIn))),
			IssuedAt:  _jwt.NewNumericDate(time.Now()),
		},
		UserId: t.userId,
		Role:   t.role,
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

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), *expected, *actual)
}

func (t *TokenServiceTest) TestValidateInvalidIssuer() {
	expected := errors.New("invalid token")

	payloads := tokenDto.AuthPayload{
		RegisteredClaims: _jwt.RegisteredClaims{
			Issuer:    "InvalidIssuer",
			ExpiresAt: _jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(t.jwtConfig.ExpiresIn))),
			IssuedAt:  _jwt.NewNumericDate(time.Now()),
		},
		UserId: t.userId,
		Role:   t.role,
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

	payloads := tokenDto.AuthPayload{
		RegisteredClaims: _jwt.RegisteredClaims{
			Issuer:    t.jwtConfig.Issuer,
			ExpiresAt: _jwt.NewNumericDate(time.Now().Add(time.Second * (-time.Duration(t.jwtConfig.ExpiresIn)))),
			IssuedAt:  _jwt.NewNumericDate(time.Now()),
		},
		UserId: t.userId,
		Role:   t.role,
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
