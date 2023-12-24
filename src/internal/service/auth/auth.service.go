package auth

import (
	"context"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	userRepo "github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/token"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

type serviceImpl struct {
	authProto.UnimplementedAuthServiceServer
	userRepo     userRepo.Repository
	tokenService token.Service
	bcryptUtil   utils.IBcryptUtil
	config       config.App
}

func NewService(userRepo userRepo.Repository, tokenService token.Service, config config.App) *serviceImpl {
	bcryptUtil := utils.NewBcryptUtil()
	return &serviceImpl{userRepo: userRepo, tokenService: tokenService, bcryptUtil: bcryptUtil, config: config}
}

func (s *serviceImpl) Validate(_ context.Context, request *authProto.ValidateRequest) (*authProto.ValidateResponse, error) {
	// call tokenService.Validate
	return nil, nil
}

func (s *serviceImpl) RefreshToken(_ context.Context, request *authProto.RefreshTokenRequest) (*authProto.RefreshTokenResponse, error) {
	// find user with refreshToken
	// create new Credential
	// update refreshToken in db
	return nil, nil
}

func (s *serviceImpl) Signup(_ context.Context, request *authProto.SignupRequest) (*authProto.SignupResponse, error) {
	// hash password with bcrypt
	// initialize model.User
	// create User in db
	return nil, nil
}

func (s *serviceImpl) SignIn(_ context.Context, request *authProto.SignInRequest) (*authProto.SignInResponse, error) {
	// find user with email
	// compare password with hashed password
	// if matched, then call tokenService.CreateCredential
	// update refreshToken in db
	return nil, nil
}
