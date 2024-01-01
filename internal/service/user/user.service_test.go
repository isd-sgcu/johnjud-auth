package user

import (
	"context"
	"errors"
	"github.com/isd-sgcu/johnjud-auth/cfgldr"
	model2 "github.com/isd-sgcu/johnjud-auth/internal/domain/model"
	mock "github.com/isd-sgcu/johnjud-auth/mocks/repository/user"
	"github.com/isd-sgcu/johnjud-auth/mocks/utils"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/google/uuid"
	proto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/user/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type UserServiceTest struct {
	suite.Suite
	config            *cfgldr.App
	User              *model2.User
	UpdateUser        *model2.User
	UserDto           *proto.User
	UserDtoNoPassword *proto.User
	HashedPassword    string
	UpdateUserReqMock *proto.UpdateUserRequest
}

func TestUserService(t *testing.T) {
	suite.Run(t, new(UserServiceTest))
}

func (t *UserServiceTest) SetupTest() {
	t.User = &model2.User{
		Base: model2.Base{
			ID:        uuid.New(),
			CreatedAt: time.Time{},
			UpdatedAt: time.Time{},
			DeletedAt: gorm.DeletedAt{},
		},
		Email:     faker.Email(),
		Password:  faker.Password(),
		Firstname: faker.Username(),
		Lastname:  faker.Username(),
		Role:      "user",
	}

	t.UserDto = &proto.User{
		Id:        t.User.ID.String(),
		Email:     t.User.Email,
		Password:  t.User.Password,
		Firstname: t.User.Firstname,
		Lastname:  t.User.Lastname,
		Role:      string(t.User.Role),
	}

	t.UserDtoNoPassword = &proto.User{
		Id:        t.User.ID.String(),
		Email:     t.User.Email,
		Firstname: t.User.Firstname,
		Lastname:  t.User.Lastname,
		Role:      string(t.User.Role),
	}

	t.UpdateUserReqMock = &proto.UpdateUserRequest{
		Id:        t.User.ID.String(),
		Email:     t.User.Email,
		Password:  t.User.Password,
		Firstname: t.User.Firstname,
		Lastname:  t.User.Lastname,
	}

	t.HashedPassword = faker.Password()

	t.UpdateUser = &model2.User{
		Email:     t.User.Email,
		Password:  t.HashedPassword,
		Firstname: t.User.Firstname,
		Lastname:  t.User.Lastname,
	}
}

func (t *UserServiceTest) TestFindOneSuccess() {
	want := &proto.FindOneUserResponse{User: t.UserDtoNoPassword}

	repo := &mock.UserRepositoryMock{}
	repo.On("FindById", t.User.ID.String(), &model2.User{}).Return(t.User, nil)

	brcyptUtil := &utils.BcryptUtilMock{}
	srv := NewService(repo, brcyptUtil)
	actual, err := srv.FindOne(context.Background(), &proto.FindOneUserRequest{Id: t.User.ID.String()})

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), want, actual)
}

func (t *UserServiceTest) TestFindOneInternalErr() {
	repo := &mock.UserRepositoryMock{}
	repo.On("FindById", t.User.ID.String(), &model2.User{}).Return(nil, errors.New("Not found user"))

	brcyptUtil := &utils.BcryptUtilMock{}
	srv := NewService(repo, brcyptUtil)
	actual, err := srv.FindOne(context.Background(), &proto.FindOneUserRequest{Id: t.User.ID.String()})

	st, ok := status.FromError(err)

	assert.True(t.T(), ok)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
}

func (t *UserServiceTest) TestUpdateSuccess() {
	want := &proto.UpdateUserResponse{User: t.UserDtoNoPassword}

	repo := &mock.UserRepositoryMock{}
	repo.On("Update", t.User.ID.String(), t.UpdateUser).Return(t.User, nil)

	brcyptUtil := &utils.BcryptUtilMock{}
	brcyptUtil.On("GenerateHashedPassword", t.User.Password).Return(t.HashedPassword, nil)

	srv := NewService(repo, brcyptUtil)
	actual, err := srv.Update(context.Background(), t.UpdateUserReqMock)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), want, actual)
}

func (t *UserServiceTest) TestUpdateInternalErr() {
	repo := &mock.UserRepositoryMock{}
	repo.On("Update", t.User.ID.String(), t.UpdateUser).Return(nil, errors.New("Not found user"))

	brcyptUtil := &utils.BcryptUtilMock{}
	brcyptUtil.On("GenerateHashedPassword", t.User.Password).Return(t.HashedPassword, nil)

	srv := NewService(repo, brcyptUtil)
	actual, err := srv.Update(context.Background(), t.UpdateUserReqMock)

	st, ok := status.FromError(err)

	assert.True(t.T(), ok)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
}

func (t *UserServiceTest) TestDeleteSuccess() {
	want := &proto.DeleteUserResponse{Success: true}

	repo := &mock.UserRepositoryMock{}
	repo.On("Delete", t.User.ID.String()).Return(nil)

	brcyptUtil := &utils.BcryptUtilMock{}
	srv := NewService(repo, brcyptUtil)
	actual, err := srv.Delete(context.Background(), &proto.DeleteUserRequest{Id: t.UserDto.Id})

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), want, actual)
}

func (t *UserServiceTest) TestDeleteInternalErr() {
	repo := &mock.UserRepositoryMock{}
	repo.On("Delete", t.User.ID.String()).Return(errors.New("Not found user"))

	brcyptUtil := &utils.BcryptUtilMock{}
	srv := NewService(repo, brcyptUtil)
	actual, err := srv.Delete(context.Background(), &proto.DeleteUserRequest{Id: t.UserDto.Id})

	st, ok := status.FromError(err)
	assert.True(t.T(), ok)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.Internal, st.Code())
}
