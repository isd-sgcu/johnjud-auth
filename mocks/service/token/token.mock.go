package token

import (
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/internal/domain/dto/token"
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

func (m *TokenServiceMock) RemoveAccessTokenCache(authSessionId string) error {
	args := m.Called(authSessionId)
	return args.Error(0)
}

func (m *TokenServiceMock) FindRefreshTokenCache(refreshToken string) (*tokenDto.RefreshTokenCache, error) {
	args := m.Called(refreshToken)
	if args.Get(0) != nil {
		return args.Get(0).(*tokenDto.RefreshTokenCache), nil
	}

	return nil, args.Error(1)
}

func (m *TokenServiceMock) RemoveRefreshTokenCache(refreshToken string) error {
	args := m.Called(refreshToken)
	return args.Error(0)
}

func (m *TokenServiceMock) CreateResetPasswordToken(userId string) (string, error) {
	args := m.Called(userId)
	if args.Get(0) != "" {
		return args.Get(0).(string), nil
	}

	return "", args.Error(1)
}

func (m *TokenServiceMock) FindResetPasswordToken(token string) (*tokenDto.ResetPasswordTokenCache, error) {
	args := m.Called(token)
	if args.Get(0) != nil {
		return args.Get(0).(*tokenDto.ResetPasswordTokenCache), nil
	}

	return nil, args.Error(1)
}

func (m *TokenServiceMock) RemoveResetPasswordToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}
