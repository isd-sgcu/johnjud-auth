package auth

import (
	"context"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/repository/cache"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/token"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type serviceImpl struct {
	authProto.UnimplementedAuthServiceServer
	userRepo     user.Repository
	tokenService token.Service
	bcryptUtil   utils.IBcryptUtil
	cacheRepo    cache.Repository
}

func NewService(userRepo user.Repository, tokenService token.Service, bcryptUtil utils.IBcryptUtil, cacheRepo cache.Repository) *serviceImpl {
	return &serviceImpl{
		userRepo:     userRepo,
		tokenService: tokenService,
		bcryptUtil:   bcryptUtil,
		cacheRepo:    cacheRepo,
	}
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

func (s *serviceImpl) Signup(_ context.Context, request *authProto.SignUpRequest) (*authProto.SignUpResponse, error) {
	hashPassword, err := s.bcryptUtil.GenerateHashedPassword(request.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	createUser := &model.User{
		Email:     request.Email,
		Password:  hashPassword,
		Firstname: request.FirstName,
		Lastname:  request.LastName,
		Role:      constant.USER,
	}
	err = s.userRepo.Create(createUser)
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, status.Error(codes.AlreadyExists, constant.DuplicateEmailErrorMessage)
		}
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.SignUpResponse{
		Id:        createUser.ID.String(),
		FirstName: createUser.Firstname,
		LastName:  createUser.Lastname,
		Email:     createUser.Email,
	}, nil
}

func (s *serviceImpl) SignIn(_ context.Context, request *authProto.SignInRequest) (*authProto.SignInResponse, error) {
	user := &model.User{}
	err := s.userRepo.FindByEmail(request.Email, user)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, constant.IncorrectEmailPasswordErrorMessage)
	}

	err = s.bcryptUtil.CompareHashedPassword(user.Password, request.Password)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, constant.IncorrectEmailPasswordErrorMessage)
	}

	credential, err := s.tokenService.CreateCredential(user.ID.String(), user.Role)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.SignInResponse{Credential: credential}, nil
}

func (s *serviceImpl) SignOut(_ context.Context, request *authProto.SignOutRequest) (*authProto.SignOutResponse, error) {
	return nil, nil
}
