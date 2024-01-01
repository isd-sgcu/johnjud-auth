package auth

import (
	"context"
	constant2 "github.com/isd-sgcu/johnjud-auth/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/internal/domain/dto/token"
	model2 "github.com/isd-sgcu/johnjud-auth/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/mocks/repository/auth"
	"github.com/isd-sgcu/johnjud-auth/mocks/repository/user"
	"github.com/isd-sgcu/johnjud-auth/mocks/service/token"
	"github.com/isd-sgcu/johnjud-auth/mocks/utils"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type AuthServiceTest struct {
	suite.Suite
	ctx            context.Context
	signupRequest  *authProto.SignUpRequest
	signInRequest  *authProto.SignInRequest
	signOutRequest *authProto.SignOutRequest
}

func TestAuthService(t *testing.T) {
	suite.Run(t, new(AuthServiceTest))
}

func (t *AuthServiceTest) SetupTest() {
	ctx := context.Background()
	signupRequest := &authProto.SignUpRequest{
		FirstName: faker.FirstName(),
		LastName:  faker.LastName(),
		Email:     faker.Email(),
		Password:  faker.Password(),
	}
	signInRequest := &authProto.SignInRequest{
		Email:    faker.Email(),
		Password: faker.Password(),
	}
	signOutRequest := &authProto.SignOutRequest{
		Token: faker.Word(),
	}

	t.ctx = ctx
	t.signupRequest = signupRequest
	t.signInRequest = signInRequest
	t.signOutRequest = signOutRequest
}

func (t *AuthServiceTest) TestSignupSuccess() {
	hashedPassword := faker.Password()
	newUser := &model2.User{
		Email:     t.signupRequest.Email,
		Password:  hashedPassword,
		Firstname: t.signupRequest.FirstName,
		Lastname:  t.signupRequest.LastName,
		Role:      constant2.USER,
	}
	createdUser := &model2.User{
		Base: model2.Base{
			ID:        uuid.New(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Email:     newUser.Email,
		Password:  newUser.Password,
		Firstname: newUser.Firstname,
		Lastname:  newUser.Lastname,
		Role:      newUser.Role,
	}

	expected := &authProto.SignUpResponse{
		Id:        createdUser.ID.String(),
		FirstName: createdUser.Firstname,
		LastName:  createdUser.Lastname,
		Email:     createdUser.Email,
	}

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return(hashedPassword, nil)
	userRepo.On("Create", newUser).Return(createdUser, nil)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignUp(t.ctx, t.signupRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected.Id, actual.Id)
}

func (t *AuthServiceTest) TestSignupHashPasswordFailed() {
	hashPasswordErr := errors.New("Hash password error")

	expected := status.Error(codes.Internal, constant2.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return("", hashPasswordErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignUp(t.ctx, t.signupRequest)

	status, ok := status.FromError(err)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignupCreateUserDuplicateConstraint() {
	hashedPassword := faker.Password()
	newUser := &model2.User{
		Email:     t.signupRequest.Email,
		Password:  hashedPassword,
		Firstname: t.signupRequest.FirstName,
		Lastname:  t.signupRequest.LastName,
		Role:      constant2.USER,
	}
	createUserErr := gorm.ErrDuplicatedKey

	expected := status.Error(codes.AlreadyExists, constant2.DuplicateEmailErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return(hashedPassword, nil)
	userRepo.On("Create", newUser).Return(nil, createUserErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignUp(t.ctx, t.signupRequest)

	status, ok := status.FromError(err)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.AlreadyExists, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignupCreateUserInternalFailed() {
	hashedPassword := faker.Password()
	newUser := &model2.User{
		Email:     t.signupRequest.Email,
		Password:  hashedPassword,
		Firstname: t.signupRequest.FirstName,
		Lastname:  t.signupRequest.LastName,
		Role:      constant2.USER,
	}
	createUserErr := errors.New("Internal server error")

	expected := status.Error(codes.Internal, constant2.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return(hashedPassword, nil)
	userRepo.On("Create", newUser).Return(nil, createUserErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignUp(t.ctx, t.signupRequest)

	status, ok := status.FromError(err)

	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignInSuccess() {
	existUser := &model2.User{
		Base: model2.Base{
			ID: uuid.New(),
		},
		Email:     t.signInRequest.Email,
		Password:  faker.Password(),
		Firstname: faker.FirstName(),
		Lastname:  faker.LastName(),
		Role:      constant2.USER,
	}
	newAuthSession := &model2.AuthSession{
		UserID: existUser.ID,
	}
	credential := &authProto.Credential{
		AccessToken:  faker.Word(),
		RefreshToken: faker.Word(),
		ExpiresIn:    3600,
	}

	expected := &authProto.SignInResponse{Credential: credential}

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model2.User{}).Return(existUser, nil)
	bcryptUtil.On("CompareHashedPassword", existUser.Password, t.signInRequest.Password).Return(nil)
	authRepo.EXPECT().Create(newAuthSession).Return(nil)
	tokenService.On("CreateCredential", existUser.ID.String(), existUser.Role, newAuthSession.ID.String()).Return(credential, nil)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected.Credential.AccessToken, actual.Credential.AccessToken)
	assert.Equal(t.T(), expected.Credential.RefreshToken, actual.Credential.RefreshToken)
}

func (t *AuthServiceTest) TestSignInUserNotFound() {
	findUserErr := gorm.ErrRecordNotFound

	expected := status.Error(codes.PermissionDenied, constant2.IncorrectEmailPasswordErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model2.User{}).Return(nil, findUserErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	status, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.PermissionDenied, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignInUnmatchedPassword() {
	existUser := &model2.User{
		Base: model2.Base{
			ID: uuid.New(),
		},
		Email:     t.signInRequest.Email,
		Password:  faker.Password(),
		Firstname: faker.FirstName(),
		Lastname:  faker.LastName(),
		Role:      constant2.USER,
	}
	comparePwdErr := errors.New("Unmatched password")

	expected := status.Error(codes.PermissionDenied, constant2.IncorrectEmailPasswordErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model2.User{}).Return(existUser, nil)
	bcryptUtil.On("CompareHashedPassword", existUser.Password, t.signInRequest.Password).Return(comparePwdErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	status, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.PermissionDenied, status.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignInCreateAuthSessionFailed() {
	existUser := &model2.User{
		Base: model2.Base{
			ID: uuid.New(),
		},
		Email:     t.signInRequest.Email,
		Password:  faker.Password(),
		Firstname: faker.FirstName(),
		Lastname:  faker.LastName(),
		Role:      constant2.USER,
	}
	newAuthSession := &model2.AuthSession{
		UserID: existUser.ID,
	}
	createAuthSessionErr := errors.New("Internal server error")

	expected := status.Error(codes.Internal, constant2.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model2.User{}).Return(existUser, nil)
	bcryptUtil.On("CompareHashedPassword", existUser.Password, t.signInRequest.Password).Return(nil)
	authRepo.EXPECT().Create(newAuthSession).Return(createAuthSessionErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignIn(t.ctx, t.signInRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignInCreateCredentialFailed() {
	existUser := &model2.User{
		Base: model2.Base{
			ID: uuid.New(),
		},
		Email:     t.signInRequest.Email,
		Password:  faker.Password(),
		Firstname: faker.FirstName(),
		Lastname:  faker.LastName(),
		Role:      constant2.USER,
	}
	newAuthSession := &model2.AuthSession{
		UserID: existUser.ID,
	}
	createCredentialErr := errors.New("Failed to create credential")

	expected := status.Error(codes.Internal, constant2.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model2.User{}).Return(existUser, nil)
	bcryptUtil.On("CompareHashedPassword", existUser.Password, t.signInRequest.Password).Return(nil)
	authRepo.EXPECT().Create(newAuthSession).Return(nil)
	tokenService.On("CreateCredential", existUser.ID.String(), existUser.Role, newAuthSession.ID.String()).Return(nil, createCredentialErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
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

func (t *AuthServiceTest) TestSignOutSuccess() {
	userCredential := &tokenDto.UserCredential{
		UserID:        faker.UUIDDigit(),
		Role:          constant2.USER,
		AuthSessionID: faker.UUIDDigit(),
		RefreshToken:  faker.UUIDDigit(),
	}

	expected := &authProto.SignOutResponse{
		IsSuccess: true,
	}

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("Validate", t.signOutRequest.Token).Return(userCredential, nil)
	tokenService.On("RemoveTokenCache", userCredential.RefreshToken).Return(nil)
	authRepo.EXPECT().Delete(userCredential.AuthSessionID).Return(nil)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignOut(t.ctx, t.signOutRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected, actual)
}

func (t *AuthServiceTest) TestSignOutValidateFailed() {
	validateErr := errors.New("internal server error")
	expected := status.Error(codes.Internal, constant2.InternalServerErrorMessage)
	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("Validate", t.signOutRequest.Token).Return(nil, validateErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignOut(t.ctx, t.signOutRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignOutRemoveTokenCacheFailed() {
	userCredential := &tokenDto.UserCredential{
		UserID:        faker.UUIDDigit(),
		Role:          constant2.USER,
		AuthSessionID: faker.UUIDDigit(),
		RefreshToken:  faker.UUIDDigit(),
	}
	removeTokenErr := errors.New("internal server error")

	expected := status.Error(codes.Internal, constant2.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("Validate", t.signOutRequest.Token).Return(userCredential, nil)
	tokenService.On("RemoveTokenCache", userCredential.RefreshToken).Return(removeTokenErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignOut(t.ctx, t.signOutRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignOutDeleteAuthSessionFailed() {
	userCredential := &tokenDto.UserCredential{
		UserID:        faker.UUIDDigit(),
		Role:          constant2.USER,
		AuthSessionID: faker.UUIDDigit(),
		RefreshToken:  faker.UUIDDigit(),
	}
	deleteAuthErr := errors.New("internal server error")

	expected := status.Error(codes.Internal, constant2.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("Validate", t.signOutRequest.Token).Return(userCredential, nil)
	tokenService.On("RemoveTokenCache", userCredential.RefreshToken).Return(nil)
	authRepo.EXPECT().Delete(userCredential.AuthSessionID).Return(deleteAuthErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.SignOut(t.ctx, t.signOutRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}
