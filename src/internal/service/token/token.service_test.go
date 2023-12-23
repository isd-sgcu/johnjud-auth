package token

import (
	"github.com/go-faker/faker/v4"
	_jwt "github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/jwt"
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
	accessToken := "testAccessToken"
	refreshToken := uuid.New()
	jwtConfig := &config.Jwt{
		Secret:    "testSecret",
		ExpiresIn: 3600,
		Issuer:    "testIssuer",
	}
	validateToken := "testValidateToken"

	t.userId = userId
	t.accessToken = accessToken
	t.refreshToken = &refreshToken
	t.jwtConfig = jwtConfig
	t.validateToken = validateToken
}

func (t *TokenServiceTest) TestCreateCredentialSuccess() {
	expected := &authProto.Credential{
		AccessToken:  t.accessToken,
		RefreshToken: t.refreshToken.String(),
		ExpiresIn:    int32(t.jwtConfig.ExpiresIn),
	}

	jwtService := jwt.JwtServiceMock{}
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("SignAuth", t.userId).Return(t.accessToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)
	uuidUtil.On("GetNewUUID").Return(t.refreshToken)

	tokenSvc := NewService(&jwtService, &uuidUtil)
	actual, err := tokenSvc.CreateCredential(t.userId)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), *expected, *actual)
}

func (t *TokenServiceTest) TestCreateCredentialFailed() {
	signAuthError := errors.New("")
	expected := errors.New("")

	jwtService := jwt.JwtServiceMock{}
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("SignAuth", t.userId).Return("", signAuthError)

	tokenSvc := NewService(&jwtService, &uuidUtil)
	actual, err := tokenSvc.CreateCredential(t.userId)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected, err)
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
	}

	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}

	jwtService := jwt.JwtServiceMock{}
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)

	tokenSvc := NewService(&jwtService, &uuidUtil)
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
	}

	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}

	jwtService := jwt.JwtServiceMock{}
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)

	tokenSvc := NewService(&jwtService, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected, err)
}

func (t *TokenServiceTest) TestValidateExpireToken() {
	expected := errors.New("expired token")

	payloads := tokenDto.AuthPayload{
		RegisteredClaims: _jwt.RegisteredClaims{
			Issuer:    "InvalidIssuer",
			ExpiresAt: _jwt.NewNumericDate(time.Now().Add(time.Second * (-time.Duration(t.jwtConfig.ExpiresIn)))),
			IssuedAt:  _jwt.NewNumericDate(time.Now()),
		},
		UserId: t.userId,
	}

	jwtToken := &_jwt.Token{
		Method: _jwt.SigningMethodHS256,
		Claims: payloads,
	}

	jwtService := jwt.JwtServiceMock{}
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(jwtToken, nil)
	jwtService.On("GetConfig").Return(t.jwtConfig)

	tokenSvc := NewService(&jwtService, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected, err)
}

func (t *TokenServiceTest) TestValidateVerifyFailed() {
	expected := errors.New("invalid token")

	jwtService := jwt.JwtServiceMock{}
	uuidUtil := utils.UuidUtilMock{}

	jwtService.On("VerifyAuth", t.validateToken).Return(nil, expected)

	tokenSvc := NewService(&jwtService, &uuidUtil)
	actual, err := tokenSvc.Validate(t.validateToken)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected, err)
}

func (t *TokenServiceTest) TestCreateRefreshTokenSuccess() {
	expected := t.refreshToken.String()

	jwtService := jwt.JwtServiceMock{}
	uuidUtil := utils.UuidUtilMock{}

	uuidUtil.On("GetNewUUID").Return(t.refreshToken)

	tokenSvc := NewService(&jwtService, &uuidUtil)
	actual := tokenSvc.CreateRefreshToken()

	assert.Equal(t.T(), expected, actual)
}
