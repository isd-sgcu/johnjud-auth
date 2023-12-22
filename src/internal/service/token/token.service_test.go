package token

import (
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	"github.com/stretchr/testify/suite"
	"testing"
)

type TokenServiceTest struct {
	suite.Suite
	jwtService *jwt.Service
}

func TestTokenService(t *testing.T) {
	suite.Run(t, new(TokenServiceTest))
}

func (t *TokenServiceTest) SetupTest() {

}
