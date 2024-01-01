package auth

import (
	"context"
	constant2 "github.com/isd-sgcu/johnjud-auth/internal/constant"
	model2 "github.com/isd-sgcu/johnjud-auth/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/auth"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/user"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/token"

	"github.com/google/uuid"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type serviceImpl struct {
	authProto.UnimplementedAuthServiceServer
	authRepo     auth.Repository
	userRepo     user.Repository
	tokenService token.Service
	bcryptUtil   utils.IBcryptUtil
}

func NewService(authRepo auth.Repository, userRepo user.Repository, tokenService token.Service, bcryptUtil utils.IBcryptUtil) *serviceImpl {
	return &serviceImpl{
		authRepo:     authRepo,
		userRepo:     userRepo,
		tokenService: tokenService,
		bcryptUtil:   bcryptUtil,
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

func (s *serviceImpl) SignUp(_ context.Context, request *authProto.SignUpRequest) (*authProto.SignUpResponse, error) {
	hashPassword, err := s.bcryptUtil.GenerateHashedPassword(request.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, constant2.InternalServerErrorMessage)
	}

	createUser := &model2.User{
		Email:     request.Email,
		Password:  hashPassword,
		Firstname: request.FirstName,
		Lastname:  request.LastName,
		Role:      constant2.USER,
	}
	err = s.userRepo.Create(createUser)
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, status.Error(codes.AlreadyExists, constant2.DuplicateEmailErrorMessage)
		}
		return nil, status.Error(codes.Internal, constant2.InternalServerErrorMessage)
	}

	return &authProto.SignUpResponse{
		Id:        createUser.ID.String(),
		FirstName: createUser.Firstname,
		LastName:  createUser.Lastname,
		Email:     createUser.Email,
	}, nil
}

func (s *serviceImpl) SignIn(_ context.Context, request *authProto.SignInRequest) (*authProto.SignInResponse, error) {
	user := &model2.User{}
	err := s.userRepo.FindByEmail(request.Email, user)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, constant2.IncorrectEmailPasswordErrorMessage)
	}

	err = s.bcryptUtil.CompareHashedPassword(user.Password, request.Password)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, constant2.IncorrectEmailPasswordErrorMessage)
	}

	credential, err := s.createAuthSession(user.ID, user.Role)
	if err != nil {
		return nil, status.Error(codes.Internal, constant2.InternalServerErrorMessage)
	}

	return &authProto.SignInResponse{Credential: credential}, nil
}

func (s *serviceImpl) SignOut(_ context.Context, request *authProto.SignOutRequest) (*authProto.SignOutResponse, error) {
	userCredential, err := s.tokenService.Validate(request.Token)
	if err != nil {
		return nil, status.Error(codes.Internal, constant2.InternalServerErrorMessage)
	}

	err = s.tokenService.RemoveTokenCache(userCredential.RefreshToken)
	if err != nil {
		return nil, status.Error(codes.Internal, constant2.InternalServerErrorMessage)
	}

	err = s.authRepo.Delete(userCredential.AuthSessionID)
	if err != nil {
		return nil, status.Error(codes.Internal, constant2.InternalServerErrorMessage)
	}

	return &authProto.SignOutResponse{IsSuccess: true}, nil
}

func (s *serviceImpl) createAuthSession(userId uuid.UUID, role constant2.Role) (*authProto.Credential, error) {
	createAuthSession := &model2.AuthSession{
		UserID: userId,
	}
	err := s.authRepo.Create(createAuthSession)
	if err != nil {
		return nil, errors.New("Internal server error")
	}

	return s.tokenService.CreateCredential(userId.String(), role, createAuthSession.ID.String())
}
