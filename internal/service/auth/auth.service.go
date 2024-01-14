package auth

import (
	"context"
	"fmt"
	"github.com/isd-sgcu/johnjud-auth/cfgldr"
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/auth"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/user"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/email"
	"github.com/isd-sgcu/johnjud-auth/pkg/service/token"
	"github.com/rs/zerolog/log"

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
	emailService email.Service
	bcryptUtil   utils.IBcryptUtil
	config       cfgldr.Auth
}

func NewService(authRepo auth.Repository, userRepo user.Repository, tokenService token.Service, emailService email.Service, bcryptUtil utils.IBcryptUtil, config cfgldr.Auth) authProto.AuthServiceServer {
	return &serviceImpl{
		authRepo:     authRepo,
		userRepo:     userRepo,
		tokenService: tokenService,
		emailService: emailService,
		bcryptUtil:   bcryptUtil,
		config:       config,
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

	err = s.tokenService.RemoveRefreshTokenCache(request.RefreshToken)
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
		log.Error().
			Err(err).
			Str("service", "auth").
			Str("module", "signin").
			Msg("Error creating auth session")
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	credential, err := s.tokenService.CreateCredential(user.ID.String(), user.Role, createAuthSession.ID.String())
	if err != nil {
		log.Error().
			Err(err).
			Str("service", "auth").
			Str("module", "signin").
			Msg("Error creating credential")
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.SignInResponse{Credential: credential}, nil
}

func (s *serviceImpl) SignOut(_ context.Context, request *authProto.SignOutRequest) (*authProto.SignOutResponse, error) {
	userCredential, err := s.tokenService.Validate(request.Token)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	err = s.tokenService.RemoveRefreshTokenCache(userCredential.RefreshToken)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	err = s.tokenService.RemoveAccessTokenCache(userCredential.AuthSessionID)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	err = s.authRepo.Delete(userCredential.AuthSessionID)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.SignOutResponse{IsSuccess: true}, nil
}

func (s *serviceImpl) ForgotPassword(_ context.Context, request *authProto.ForgotPasswordRequest) (*authProto.ForgotPasswordResponse, error) {
	user := &model.User{}
	err := s.userRepo.FindByEmail(request.Email, user)
	if err != nil {
		return nil, status.Error(codes.NotFound, constant.UserNotFoundErrorMessage)
	}

	resetPasswordToken, err := s.tokenService.CreateResetPasswordToken(user.ID.String())
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	resetPasswordURL := fmt.Sprintf("%s/reset-password/%s", s.config.ClientURL, resetPasswordToken)
	emailSubject := constant.ResetPasswordSubject
	emailContent := fmt.Sprintf("Please click the following url to reset password %s", resetPasswordURL)
	if err := s.emailService.SendEmail(emailSubject, user.Firstname, user.Email, emailContent); err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.ForgotPasswordResponse{
		Url: resetPasswordURL,
	}, nil
}

func (s *serviceImpl) ResetPassword(_ context.Context, request *authProto.ResetPasswordRequest) (*authProto.ResetPasswordResponse, error) {
	resetTokenCache, err := s.tokenService.FindResetPasswordToken(request.Token)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	userDb := &model.User{}
	if err := s.userRepo.FindById(resetTokenCache.UserID, userDb); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, constant.UserNotFoundErrorMessage)
		}
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	err = s.bcryptUtil.CompareHashedPassword(userDb.Password, request.Password)
	if err == nil {
		return nil, status.Error(codes.InvalidArgument, constant.IncorrectPasswordErrorMessage)
	}

	hashPassword, err := s.bcryptUtil.GenerateHashedPassword(request.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	userDb.Password = hashPassword
	if err := s.userRepo.Update(resetTokenCache.UserID, userDb); err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	if err := s.tokenService.RemoveResetPasswordToken(request.Token); err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	return &authProto.ResetPasswordResponse{
		IsSuccess: true,
	}, nil
}
