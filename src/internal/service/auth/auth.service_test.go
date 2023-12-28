package auth

import (
	"context"
	"github.com/go-faker/faker/v4"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	mock_auth "github.com/isd-sgcu/johnjud-auth/src/mocks/repository/auth"
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
	newUser := &model.User{
		Email:     t.signupRequest.Email,
		Password:  hashedPassword,
		Firstname: t.signupRequest.FirstName,
		Lastname:  t.signupRequest.LastName,
		Role:      constant.USER,
	}
	createdUser := &model.User{
		Base: model.Base{
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
	actual, err := authSvc.Signup(t.ctx, t.signupRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected.Id, actual.Id)
}

func (t *AuthServiceTest) TestSignupHashPasswordFailed() {
	hashPasswordErr := errors.New("Hash password error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return("", hashPasswordErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
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
		Email:     t.signupRequest.Email,
		Password:  hashedPassword,
		Firstname: t.signupRequest.FirstName,
		Lastname:  t.signupRequest.LastName,
		Role:      constant.USER,
	}
	createUserErr := gorm.ErrDuplicatedKey

	expected := status.Error(codes.AlreadyExists, constant.DuplicateEmailErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return(hashedPassword, nil)
	userRepo.On("Create", newUser).Return(nil, createUserErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
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
		Email:     t.signupRequest.Email,
		Password:  hashedPassword,
		Firstname: t.signupRequest.FirstName,
		Lastname:  t.signupRequest.LastName,
		Role:      constant.USER,
	}
	createUserErr := errors.New("Internal server error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	bcryptUtil.On("GenerateHashedPassword", t.signupRequest.Password).Return(hashedPassword, nil)
	userRepo.On("Create", newUser).Return(nil, createUserErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
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
		Email:     t.signInRequest.Email,
		Password:  faker.Password(),
		Firstname: faker.FirstName(),
		Lastname:  faker.LastName(),
		Role:      constant.USER,
	}
	newAuthSession := &model.AuthSession{
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

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(existUser, nil)
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

	expected := status.Error(codes.PermissionDenied, constant.IncorrectEmailPasswordErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(nil, findUserErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
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
		Email:     t.signInRequest.Email,
		Password:  faker.Password(),
		Firstname: faker.FirstName(),
		Lastname:  faker.LastName(),
		Role:      constant.USER,
	}
	comparePwdErr := errors.New("Unmatched password")

	expected := status.Error(codes.PermissionDenied, constant.IncorrectEmailPasswordErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(existUser, nil)
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
	existUser := &model.User{
		Base: model.Base{
			ID: uuid.New(),
		},
		Email:     t.signInRequest.Email,
		Password:  faker.Password(),
		Firstname: faker.FirstName(),
		Lastname:  faker.LastName(),
		Role:      constant.USER,
	}
	newAuthSession := &model.AuthSession{
		UserID: existUser.ID,
	}
	createAuthSessionErr := errors.New("Internal server error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(existUser, nil)
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
	existUser := &model.User{
		Base: model.Base{
			ID: uuid.New(),
		},
		Email:     t.signInRequest.Email,
		Password:  faker.Password(),
		Firstname: faker.FirstName(),
		Lastname:  faker.LastName(),
		Role:      constant.USER,
	}
	newAuthSession := &model.AuthSession{
		UserID: existUser.ID,
	}
	createCredentialErr := errors.New("Failed to create credential")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	userRepo.On("FindByEmail", t.signInRequest.Email, &model.User{}).Return(existUser, nil)
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
	expected := &authProto.SignOutResponse{
		IsSuccess: true,
	}

	controller := gomock.NewController(t.T())

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}
	cacheRepo := mock_cache.NewMockRepository(controller)

	cacheRepo.EXPECT().AddSetMember(constant.BlacklistTokenCacheKey, t.signOutRequest.Token).Return(true, nil)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil, cacheRepo)
	actual, err := authSvc.SignOut(t.ctx, t.signOutRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected, actual)
}

func (t *AuthServiceTest) TestSignOutAddCacheFailed() {
	setError := errors.New("Internal server error")
	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}
	cacheRepo := mock_cache.NewMockRepository(controller)

	cacheRepo.EXPECT().AddSetMember(constant.BlacklistTokenCacheKey, t.signOutRequest.Token).Return(false, setError)

	authSvc := NewService(&userRepo, &tokenService, &bcryptUtil, cacheRepo)
	actual, err := authSvc.SignOut(t.ctx, t.signOutRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st)
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}
