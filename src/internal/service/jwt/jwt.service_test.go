package jwt

import (
	"fmt"
	"github.com/go-faker/faker/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/strategy"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

type JwtServiceTest struct {
	suite.Suite
	config config.Jwt
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

	t.config = config
}

func (t *JwtServiceTest) TestSignAuthSuccess() {
	userId := faker.UUIDDigit()
	expected := "signedTokenStr"

	numericDate := jwt.NewNumericDate(time.Now())
	payloads := tokenDto.AuthPayload{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.config.Issuer,
			ExpiresAt: numericDate,
			IssuedAt:  numericDate,
		},
		UserId: userId,
	}
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": jwt.SigningMethodHS256.Alg(),
		},
		Method: jwt.SigningMethodHS256,
		Claims: payloads,
	}

	jwtStrategy := strategy.JwtStrategyMock{}
	jwtUtil := utils.JwtUtilMock{}

	jwtUtil.On("GetNumericDate").Return(numericDate)
	jwtUtil.On("GenerateJwtToken", jwt.SigningMethodHS256, payloads).Return(token)
	jwtUtil.On("SignedTokenString", token, t.config.Secret).Return(expected, nil)

	jwtSvc := NewService(t.config, &jwtStrategy, &jwtUtil)
	actual, err := jwtSvc.SignAuth(userId)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected, actual)
}

func (t *JwtServiceTest) TestSignAuthSignedStringFailed() {
	userId := faker.UUIDDigit()
	signedTokenError := errors.New("Some Error")
	expected := errors.New(fmt.Sprintf("Error while signing the token due to: %s", signedTokenError.Error()))

	numericDate := jwt.NewNumericDate(time.Now())
	payloads := tokenDto.AuthPayload{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.config.Issuer,
			ExpiresAt: numericDate,
			IssuedAt:  numericDate,
		},
		UserId: userId,
	}
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": jwt.SigningMethodHS256.Alg(),
		},
		Method: jwt.SigningMethodHS256,
		Claims: payloads,
	}

	jwtStrategy := strategy.JwtStrategyMock{}
	jwtUtil := utils.JwtUtilMock{}

	jwtUtil.On("GetNumericDate").Return(numericDate)
	jwtUtil.On("GenerateJwtToken", jwt.SigningMethodHS256, payloads).Return(token)
	jwtUtil.On("SignedTokenString", token, t.config.Secret).Return("", signedTokenError)

	jwtSvc := NewService(t.config, &jwtStrategy, &jwtUtil)
	actual, err := jwtSvc.SignAuth(userId)

	assert.Equal(t.T(), "", actual)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *JwtServiceTest) TestVerifyAuthSuccess() {

}

func (t *JwtServiceTest) TestVerifyAuthFailed() {

}

func (t *JwtServiceTest) TestGetConfigSuccess() {

}
