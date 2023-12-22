package auth

import (
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	"github.com/stretchr/testify/suite"
	"testing"
)

type AuthServiceTest struct {
	suite.Suite
	userRepo    *user.Repository
	config      config.App
	authService *serviceImpl
}

func TestAuthService(t *testing.T) {
	suite.Run(t, new(AuthServiceTest))
}

func (t *AuthServiceTest) SetupTest() {

}
