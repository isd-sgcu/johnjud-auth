package jwt

import (
	"fmt"
	"github.com/go-faker/faker/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/strategy"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

type JwtServiceTest struct {
	suite.Suite
	config      config.Jwt
	userId      string
	role        constant.Role
	numericDate *jwt.NumericDate
	payloads    tokenDto.AuthPayload
	token       *jwt.Token
}

func TestJwtService(t *testing.T) {
	suite.Run(t, new(JwtServiceTest))
}

func (t *JwtServiceTest) SetupTest() {
	config := config.Jwt{
		Secret:    "testSecret",
		ExpiresIn: 3600,
		Issuer:    "testIssuer",
	}

	userId := faker.UUIDDigit()
	role := constant.USER
	numericDate := jwt.NewNumericDate(time.Now())

	payloads := tokenDto.AuthPayload{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.config.Issuer,
			ExpiresAt: numericDate,
			IssuedAt:  numericDate,
		},
		UserId: userId,
		Role:   role,
	}

	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": jwt.SigningMethodHS256.Alg(),
		},
		Method: jwt.SigningMethodHS256,
		Claims: payloads,
	}

	t.config = config
	t.userId = userId
	t.role = role
	t.numericDate = numericDate
	t.payloads = payloads
	t.token = token
}

func (t *JwtServiceTest) TestSignAuthSuccess() {
	expected := "signedTokenStr"

	jwtStrategy := strategy.JwtStrategyMock{}
	jwtUtil := utils.JwtUtilMock{}

	jwtUtil.On("GetNumericDate", mock.AnythingOfType("time.Time")).Return(t.numericDate)
	jwtUtil.On("GenerateJwtToken", jwt.SigningMethodHS256, t.payloads).Return(t.token)
	jwtUtil.On("SignedTokenString", t.token, t.config.Secret).Return(expected, nil)

	jwtSvc := NewService(t.config, &jwtStrategy, &jwtUtil)
	actual, err := jwtSvc.SignAuth(t.userId, t.role)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected, actual)
}

func (t *JwtServiceTest) TestSignAuthSignedStringFailed() {
	signedTokenError := errors.New("Some Error")
	expected := errors.New(fmt.Sprintf("Error while signing the token due to: %s", signedTokenError.Error()))

	jwtStrategy := strategy.JwtStrategyMock{}
	jwtUtil := utils.JwtUtilMock{}

	jwtUtil.On("GetNumericDate", mock.AnythingOfType("time.Time")).Return(t.numericDate)
	jwtUtil.On("GenerateJwtToken", jwt.SigningMethodHS256, t.payloads).Return(t.token)
	jwtUtil.On("SignedTokenString", t.token, t.config.Secret).Return("", signedTokenError)

	jwtSvc := NewService(t.config, &jwtStrategy, &jwtUtil)
	actual, err := jwtSvc.SignAuth(t.userId, t.role)

	assert.Equal(t.T(), "", actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *JwtServiceTest) TestVerifyAuthSuccess() {
	tokenStr := "validSignedToken"
	expected := t.token

	jwtStrategy := strategy.JwtStrategyMock{}
	jwtUtil := utils.JwtUtilMock{}

	jwtUtil.On("ParseToken", tokenStr, mock.AnythingOfType("jwt.Keyfunc")).Return(expected, nil)

	jwtSvc := NewService(t.config, &jwtStrategy, &jwtUtil)
	actual, err := jwtSvc.VerifyAuth(tokenStr)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), *expected, *actual)
}

func (t *JwtServiceTest) TestVerifyAuthFailed() {
	tokenStr := "invalidSignedToken"
	expected := errors.New("invalid token")

	jwtStrategy := strategy.JwtStrategyMock{}
	jwtUtil := utils.JwtUtilMock{}

	jwtUtil.On("ParseToken", tokenStr, mock.AnythingOfType("jwt.Keyfunc")).Return(nil, expected)

	jwtSvc := NewService(t.config, &jwtStrategy, &jwtUtil)
	actual, err := jwtSvc.VerifyAuth(tokenStr)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), expected, err)
}

func (t *JwtServiceTest) TestGetConfigSuccess() {
	expected := &t.config

	jwtStrategy := strategy.JwtStrategyMock{}
	jwtUtil := utils.JwtUtilMock{}

	jwtSvc := NewService(t.config, &jwtStrategy, &jwtUtil)
	actual := jwtSvc.GetConfig()

	assert.Equal(t.T(), *expected, *actual)
}
