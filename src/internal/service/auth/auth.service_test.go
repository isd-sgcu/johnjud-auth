package auth

import (
	"context"
	"github.com/go-faker/faker/v4"
	"github.com/google/uuid"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/repository/user"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/service/token"
	"github.com/isd-sgcu/johnjud-auth/src/mocks/utils"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"testing"
	"time"
)

type AuthServiceTest struct {
	suite.Suite
	ctx           context.Context
	signupRequest *authProto.SignupRequest
	signInRequest *authProto.SignInRequest
}

func TestAuthService(t *testing.T) {
	suite.Run(t, new(AuthServiceTest))
}

func (t *AuthServiceTest) SetupTest() {
	ctx := context.Background()
	signupRequest := &authProto.SignupRequest{
		FirstName: faker.FirstName(),
		LastName:  faker.LastName(),
		Email:     faker.Email(),
		Password:  faker.Password(),
	}
	signInRequest := &authProto.SignInRequest{
		Email:    faker.Email(),
		Password: faker.Password(),
	}

	t.ctx = ctx
	t.signupRequest = signupRequest
	t.signInRequest = signInRequest
}

func (t *AuthServiceTest) TestSignupSuccess() {
	hashedPassword := faker.Password()
	newUser := &model.User{
		Email:        t.signupRequest.Email,
		Password:     hashedPassword,
		Firstname:    t.signupRequest.FirstName,
		Lastname:     t.signupRequest.LastName,
		Role:         constant.USER,
		RefreshToken: "",
	}
	createdUser := &model.User{
		Base: model.Base{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Email:        newUser.Email,
		Password:     newUser.Password,
		Firstname:    newUser.Firstname,
		Lastname:     newUser.Lastname,
		Role:         newUser.Role,
		RefreshToken: newUser.RefreshToken,
	}

	expected := &authProto.SignupResponse{
		Id:        createdUser.ID.String(),
		FirstName: createdUser.Firstname,
		LastName:  createdUser.Lastname,
		Email:     createdUser.Email,
	}

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return(hashedPassword, nil)
	userRepo.On("Create", newUser).Return(createdUser, nil)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.Signup(t.ctx, t.signupRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected.Id, actual.Id)
}

func (t *AuthServiceTest) TestSignupHashPasswordFailed() {
	hashPasswordErr := errors.New("Hash password error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return("", hashPasswordErr)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.Signup(t.ctx, t.signupRequest)

	status, ok := status.FromError(err)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignupCreateUserDuplicateConstraint() {
	hashedPassword := faker.Password()
	newUser := &model.User{
		Email:        t.signupRequest.Email,
		Password:     hashedPassword,
		Firstname:    t.signupRequest.FirstName,
		Lastname:     t.signupRequest.LastName,
		Role:         constant.USER,
		RefreshToken: "",
	}
	createUserErr := gorm.ErrDuplicatedKey

	expected := status.Error(codes.AlreadyExists, constant.DuplicateEmailErrorMessage)

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return(hashedPassword, nil)
	userRepo.On("Create", newUser).Return(nil, createUserErr)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.Signup(t.ctx, t.signupRequest)

	status, ok := status.FromError(err)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.AlreadyExists, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignupCreateUserInternalFailed() {
	hashedPassword := faker.Password()
	newUser := &model.User{
		Email:        t.signupRequest.Email,
		Password:     hashedPassword,
		Firstname:    t.signupRequest.FirstName,
		Lastname:     t.signupRequest.LastName,
		Role:         constant.USER,
		RefreshToken: "",
	}
	createUserErr := errors.New("Internal server error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return(hashedPassword, nil)
	userRepo.On("Create", newUser).Return(nil, createUserErr)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.Signup(t.ctx, t.signupRequest)

	status, ok := status.FromError(err)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignInSuccess() {
	existUser := &model.User{
		Base: model.Base{
			ID: uuid.New(),
		},
		Email:        t.signInRequest.Email,
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: "",
	}
	credential := &authProto.Credential{
		AccessToken:  faker.Word(),
		RefreshToken: faker.Word(),
		ExpiresIn:    3600,
	}
	updateUser := &model.User{
		RefreshToken: credential.RefreshToken,
	}

	expected := &authProto.SignInResponse{Credential: credential}

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(existUser, nil)
	bcryptUtil.On("CompareHashedPassword", existUser.Password, t.signInRequest.Password).Return(nil)
	tokenService.On("CreateCredential", existUser.ID.String(), existUser.Role).Return(credential, nil)
	userRepo.On("Update", existUser.ID.String(), updateUser).Return(updateUser, nil)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected.Credential.AccessToken, actual.Credential.AccessToken)
	assert.Equal(t.T(), expected.Credential.RefreshToken, actual.Credential.RefreshToken)
}

func (t *AuthServiceTest) TestSignInUserNotFound() {
	findUserErr := gorm.ErrRecordNotFound

	expected := status.Error(codes.PermissionDenied, constant.IncorrectEmailPasswordErrorMessage)

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(nil, findUserErr)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	status, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.PermissionDenied, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignInUnmatchedPassword() {
	existUser := &model.User{
		Base: model.Base{
			ID: uuid.New(),
		},
		Email:        t.signInRequest.Email,
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: "",
	}
	comparePwdErr := errors.New("Unmatched password")

	expected := status.Error(codes.PermissionDenied, constant.IncorrectEmailPasswordErrorMessage)

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(existUser, nil)
	bcryptUtil.On("CompareHashedPassword", existUser.Password, t.signInRequest.Password).Return(comparePwdErr)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	status, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.PermissionDenied, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignInCreateCredentialFailed() {
	existUser := &model.User{
		Base: model.Base{
			ID: uuid.New(),
		},
		Email:        t.signInRequest.Email,
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: "",
	}
	createCredentialErr := errors.New("Failed to create credential")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(existUser, nil)
	bcryptUtil.On("CompareHashedPassword", existUser.Password, t.signInRequest.Password).Return(nil)
	tokenService.On("CreateCredential", existUser.ID.String(), existUser.Role).Return(nil, createCredentialErr)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	status, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignInUpdateTokenFailed() {
	existUser := &model.User{
		Base: model.Base{
			ID: uuid.New(),
		},
		Email:        t.signInRequest.Email,
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: "",
	}
	credential := &authProto.Credential{
		AccessToken:  faker.Word(),
		RefreshToken: faker.Word(),
		ExpiresIn:    3600,
	}
	updateUser := &model.User{
		RefreshToken: credential.RefreshToken,
	}
	updateUserErr := errors.New("Internal server error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(existUser, nil)
	bcryptUtil.On("CompareHashedPassword", existUser.Password, t.signInRequest.Password).Return(nil)
	tokenService.On("CreateCredential", existUser.ID.String(), existUser.Role).Return(credential, nil)
	userRepo.On("Update", existUser.ID.String(), updateUser).Return(nil, updateUserErr)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	status, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestValidateSuccess() {}

func (t *AuthServiceTest) TestValidateFailed() {}

func (t *AuthServiceTest) TestRefreshTokenSuccess() {}

func (t *AuthServiceTest) TestRefreshTokenNotFound() {}

func (t *AuthServiceTest) TestRefreshTokenCreateCredentialFailed() {}

func (t *AuthServiceTest) TestRefreshTokenUpdateTokenFailed() {}
