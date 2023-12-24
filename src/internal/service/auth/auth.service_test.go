package auth

import (
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/stretchr/testify/suite"
	"testing"
)

type AuthServiceTest struct {
	suite.Suite
	config *config.App
}

func TestAuthService(t *testing.T) {
	suite.Run(t, new(AuthServiceTest))
}

func (t *AuthServiceTest) SetupTest() {}

func (t *AuthServiceTest) TestSignupSuccess() {}

func (t *AuthServiceTest) TestSignupHashPasswordFailed() {}

func (t *AuthServiceTest) TestSignupCreateUserFailed() {}

func (t *AuthServiceTest) TestSignInSuccess() {}

func (t *AuthServiceTest) TestSignInUserNotFound() {}

func (t *AuthServiceTest) TestSignInUnmatchedPassword() {}

func (t *AuthServiceTest) TestSignInCreateCredentialFailed() {}

func (t *AuthServiceTest) TestSignInUpdateTokenFailed() {}

func (t *AuthServiceTest) TestValidateSuccess() {}

func (t *AuthServiceTest) TestValidateFailed() {}

func (t *AuthServiceTest) TestRefreshTokenSuccess() {}

func (t *AuthServiceTest) TestRefreshTokenNotFound() {}

func (t *AuthServiceTest) TestRefreshTokenCreateCredentialFailed() {}

func (t *AuthServiceTest) TestRefreshTokenUpdateTokenFailed() {}
