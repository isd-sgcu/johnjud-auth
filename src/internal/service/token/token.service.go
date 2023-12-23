package token

import (
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

type serviceImpl struct {
	jwtService jwt.Service
}

func NewService(jwtService jwt.Service) *serviceImpl {
	return &serviceImpl{jwtService: jwtService}
}

func (s *serviceImpl) CreateCredential(userId string, role string) (*authProto.Credential, error) {
	return nil, nil
}

func (s *serviceImpl) Validate(token string) (*tokenDto.UserCredential, error) {
	return nil, nil
}
