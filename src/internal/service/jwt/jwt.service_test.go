package jwt

import (
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/strategy"
	"github.com/stretchr/testify/suite"
	"testing"
)

type JwtServiceTest struct {
	suite.Suite
	config   config.Jwt
	strategy *strategy.JwtStrategy
}

func TestJwtService(t *testing.T) {
	suite.Run(t, new(JwtServiceTest))
}

func (t *JwtServiceTest) SetupTest() {

}
