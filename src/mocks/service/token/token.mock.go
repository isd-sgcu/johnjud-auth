package token

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/stretchr/testify/mock"
)

type TokenServiceMock struct {
	mock.Mock
}

func (m *TokenServiceMock) CreateCredential(userId string, role constant.Role, authSessionId string) (*authProto.Credential, error) {
	args := m.Called(userId, role, authSessionId)
	if args.Get(0) != nil {
		return args.Get(0).(*authProto.Credential), nil
	}

	return nil, args.Error(1)
}

func (m *TokenServiceMock) Validate(token string) (*tokenDto.UserCredential, error) {
	args := m.Called(token)
	if args.Get(0) != nil {
		return args.Get(0).(*tokenDto.UserCredential), nil
	}

	return nil, args.Error(1)
}

func (m *TokenServiceMock) CreateRefreshToken() string {
	args := m.Called()
	return args.Get(0).(string)
}
