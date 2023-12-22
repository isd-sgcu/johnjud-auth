package auth

import (
	"context"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	userRepo "github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

type serviceImpl struct {
	authProto.UnimplementedAuthServiceServer
	userRepo userRepo.Repository
	config   config.App
}

func NewService(userRepo userRepo.Repository, config config.App) *serviceImpl {
	return &serviceImpl{userRepo: userRepo, config: config}
}

func (s *serviceImpl) Validate(_ context.Context, request *authProto.ValidateRequest) (*authProto.ValidateResponse, error) {
	return nil, nil
}

func (s *serviceImpl) RefreshToken(_ context.Context, request *authProto.RefreshTokenRequest) (*authProto.RefreshTokenResponse, error) {
	return nil, nil
}

func (s *serviceImpl) Signup(_ context.Context, request *authProto.SignupRequest) (*authProto.SignupResponse, error) {
	return nil, nil
}

func (s *serviceImpl) SignIn(_ context.Context, request *authProto.SignInRequest) (*authProto.SignInResponse, error) {
	return nil, nil
}
