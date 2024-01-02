package auth

import (
	"context"
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/auth"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/user"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/token"

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

func NewService(authRepo auth.Repository, userRepo user.Repository, tokenService token.Service, bcryptUtil utils.IBcryptUtil) authProto.AuthServiceServer {
	return &serviceImpl{
		authRepo:     authRepo,
		userRepo:     userRepo,
		tokenService: tokenService,
		bcryptUtil:   bcryptUtil,
	}
}

func (s *serviceImpl) Validate(_ context.Context, request *authProto.ValidateRequest) (*authProto.ValidateResponse, error) {
	userCredential, err := s.tokenService.Validate(request.Token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, constant.InvalidTokenErrorMessage)
	}

	return &authProto.ValidateResponse{
		UserId: userCredential.UserID,
		Role:   string(userCredential.Role),
	}, nil
}

func (s *serviceImpl) RefreshToken(_ context.Context, request *authProto.RefreshTokenRequest) (*authProto.RefreshTokenResponse, error) {
	refreshTokenCache, err := s.tokenService.FindRefreshTokenCache(request.RefreshToken)
	if err != nil {
		st, _ := status.FromError(err)
		switch st.Code() {
		case codes.InvalidArgument:
			return nil, status.Error(codes.InvalidArgument, constant.InvalidTokenErrorMessage)
		default:
			return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
		}
	}
	credential, err := s.tokenService.CreateCredential(refreshTokenCache.UserID, refreshTokenCache.Role, refreshTokenCache.AuthSessionID)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	err = s.tokenService.RemoveTokenCache(request.RefreshToken)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.RefreshTokenResponse{
		Credential: credential,
	}, nil
}

func (s *serviceImpl) SignUp(_ context.Context, request *authProto.SignUpRequest) (*authProto.SignUpResponse, error) {
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

	createAuthSession := &model.AuthSession{
		UserID: user.ID,
	}
	err = s.authRepo.Create(createAuthSession)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	credential, err := s.tokenService.CreateCredential(user.ID.String(), user.Role, createAuthSession.ID.String())
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.SignInResponse{Credential: credential}, nil
}

func (s *serviceImpl) SignOut(_ context.Context, request *authProto.SignOutRequest) (*authProto.SignOutResponse, error) {
	userCredential, err := s.tokenService.Validate(request.Token)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	err = s.tokenService.RemoveTokenCache(userCredential.RefreshToken)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	err = s.authRepo.Delete(userCredential.AuthSessionID)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.SignOutResponse{IsSuccess: true}, nil
}
