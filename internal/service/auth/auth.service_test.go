package auth

import (
	"context"
	"github.com/isd-sgcu/johnjud-auth/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/internal/domain/model"
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
	ctx                 context.Context
	signupRequest       *authProto.SignUpRequest
	signInRequest       *authProto.SignInRequest
	signOutRequest      *authProto.SignOutRequest
	refreshTokenRequest *authProto.RefreshTokenRequest
	validateRequest     *authProto.ValidateRequest
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
	validateRequest := &authProto.ValidateRequest{
		Token: faker.Word(),
	}
	refreshTokenRequest := &authProto.RefreshTokenRequest{
		RefreshToken: faker.UUIDDigit(),
	}

	t.ctx = ctx
	t.signupRequest = signupRequest
	t.signInRequest = signInRequest
	t.signOutRequest = signOutRequest
	t.validateRequest = validateRequest
	t.refreshTokenRequest = refreshTokenRequest
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
	actual, err := authSvc.SignUp(t.ctx, t.signupRequest)

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
	actual, err := authSvc.SignUp(t.ctx, t.signupRequest)

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
	actual, err := authSvc.SignUp(t.ctx, t.signupRequest)

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
	actual, err := authSvc.SignUp(t.ctx, t.signupRequest)

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

func (t *AuthServiceTest) TestValidateSuccess() {
	userCredential := &tokenDto.UserCredential{
		UserID:        faker.UUIDDigit(),
		Role:          constant.USER,
		AuthSessionID: faker.UUIDDigit(),
		RefreshToken:  faker.UUIDDigit(),
	}

	expected := &authProto.ValidateResponse{
		UserId: userCredential.UserID,
		Role:   string(userCredential.Role),
	}

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("Validate", t.validateRequest.Token).Return(userCredential, nil)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.Validate(t.ctx, t.validateRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected, actual)
}

func (t *AuthServiceTest) TestValidateFailed() {
	validateErr := errors.New("invalid token")
	expected := status.Error(codes.Unauthenticated, constant.InvalidTokenErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("Validate", t.validateRequest.Token).Return(nil, validateErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.Validate(t.ctx, t.validateRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Unauthenticated, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestRefreshTokenSuccess() {
	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: faker.UUIDDigit(),
		UserID:        faker.UUIDDigit(),
		Role:          constant.USER,
	}
	credential := &authProto.Credential{
		AccessToken:  faker.Word(),
		RefreshToken: faker.UUIDDigit(),
		ExpiresIn:    3600,
	}

	expected := &authProto.RefreshTokenResponse{
		Credential: credential,
	}

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("FindRefreshTokenCache", t.refreshTokenRequest.RefreshToken).Return(refreshTokenCache, nil)
	tokenService.On("CreateCredential", refreshTokenCache.UserID, refreshTokenCache.Role, refreshTokenCache.AuthSessionID).Return(credential, nil)
	tokenService.On("RemoveTokenCache", t.refreshTokenRequest.RefreshToken).Return(nil)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.RefreshToken(t.ctx, t.refreshTokenRequest)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), expected, actual)
}

func (t *AuthServiceTest) TestRefreshTokenInvalid() {
	findTokenErr := status.Error(codes.InvalidArgument, "token not found")

	expected := status.Error(codes.InvalidArgument, constant.InvalidTokenErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("FindRefreshTokenCache", t.refreshTokenRequest.RefreshToken).Return(nil, findTokenErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.RefreshToken(t.ctx, t.refreshTokenRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.InvalidArgument, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestRefreshTokenFindTokenFailed() {
	findTokenErr := status.Error(codes.Internal, "internal error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("FindRefreshTokenCache", t.refreshTokenRequest.RefreshToken).Return(nil, findTokenErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.RefreshToken(t.ctx, t.refreshTokenRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestRefreshTokenCreateCredentialFailed() {
	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: faker.UUIDDigit(),
		UserID:        faker.UUIDDigit(),
		Role:          constant.USER,
	}
	createCredentialErr := errors.New("internal error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("FindRefreshTokenCache", t.refreshTokenRequest.RefreshToken).Return(refreshTokenCache, nil)
	tokenService.On("CreateCredential", refreshTokenCache.UserID, refreshTokenCache.Role, refreshTokenCache.AuthSessionID).Return(nil, createCredentialErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.RefreshToken(t.ctx, t.refreshTokenRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestRefreshTokenRemoveTokenFailed() {
	refreshTokenCache := &tokenDto.RefreshTokenCache{
		AuthSessionID: faker.UUIDDigit(),
		UserID:        faker.UUIDDigit(),
		Role:          constant.USER,
	}
	credential := &authProto.Credential{
		AccessToken:  faker.Word(),
		RefreshToken: faker.UUIDDigit(),
		ExpiresIn:    3600,
	}
	removeTokenErr := errors.New("internal error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

	controller := gomock.NewController(t.T())

	authRepo := mock_auth.NewMockRepository(controller)
	userRepo := user.UserRepositoryMock{}
	tokenService := token.TokenServiceMock{}
	bcryptUtil := utils.BcryptUtilMock{}

	tokenService.On("FindRefreshTokenCache", t.refreshTokenRequest.RefreshToken).Return(refreshTokenCache, nil)
	tokenService.On("CreateCredential", refreshTokenCache.UserID, refreshTokenCache.Role, refreshTokenCache.AuthSessionID).Return(credential, nil)
	tokenService.On("RemoveTokenCache", t.refreshTokenRequest.RefreshToken).Return(removeTokenErr)

	authSvc := NewService(authRepo, &userRepo, &tokenService, &bcryptUtil)
	actual, err := authSvc.RefreshToken(t.ctx, t.refreshTokenRequest)

	st, ok := status.FromError(err)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
	assert.True(t.T(), ok)
	assert.Equal(t.T(), expected.Error(), err.Error())
}

func (t *AuthServiceTest) TestSignOutSuccess() {
	userCredential := &tokenDto.UserCredential{
		UserID:        faker.UUIDDigit(),
		Role:          constant.USER,
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
	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)
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
		Role:          constant.USER,
		AuthSessionID: faker.UUIDDigit(),
		RefreshToken:  faker.UUIDDigit(),
	}
	removeTokenErr := errors.New("internal server error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

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
		Role:          constant.USER,
		AuthSessionID: faker.UUIDDigit(),
		RefreshToken:  faker.UUIDDigit(),
	}
	deleteAuthErr := errors.New("internal server error")

	expected := status.Error(codes.Internal, constant.InternalServerErrorMessage)

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
