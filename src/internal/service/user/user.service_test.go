package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bxcodec/faker/v3"
	"github.com/google/uuid"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	mock "github.com/isd-sgcu/johnjud-auth/src/mocks/user"
	proto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/user/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

type UserServiceTest struct {
	suite.Suite
	config            *config.App
	User              *model.User
	UpdateUser        *model.User
	UserDto           *proto.User
	UpdateUserReqMock *proto.UpdateUserRequest
}

func TestUserService(t *testing.T) {
	suite.Run(t, new(UserServiceTest))
}

func (t *UserServiceTest) SetupTest() {
	t.User = &model.User{
		Base: model.Base{
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

	t.UpdateUserReqMock = &proto.UpdateUserRequest{
		Id:        t.User.ID.String(),
		Email:     t.User.Email,
		Password:  t.User.Password,
		Firstname: t.User.Firstname,
		Lastname:  t.User.Lastname,
	}

	t.UpdateUser = &model.User{
		Email:     t.User.Email,
		Password:  t.User.Password,
		Firstname: t.User.Firstname,
		Lastname:  t.User.Lastname,
	}
}

func (t *UserServiceTest) TestFindOneSuccess() {
	want := &proto.FindOneUserResponse{User: t.UserDto}

	repo := &mock.RepositoryMock{}
	repo.On("FindById", t.User.ID.String(), &model.User{}).Return(t.User, nil)

	srv := NewService(repo)
	actual, err := srv.FindOne(context.Background(), &proto.FindOneUserRequest{Id: t.User.ID.String()})

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), want, actual)
}

func (t *UserServiceTest) TestFindOneNotFound() {
	repo := &mock.RepositoryMock{}
	repo.On("FindById", t.User.ID.String(), &model.User{}).Return(nil, errors.New("Not found user"))

	srv := NewService(repo)
	actual, err := srv.FindOne(context.Background(), &proto.FindOneUserRequest{Id: t.User.ID.String()})

	st, ok := status.FromError(err)

	assert.True(t.T(), ok)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.NotFound, st.Code())
}

func (t *UserServiceTest) TestUpdateSuccess() {
	want := &proto.UpdateUserResponse{User: t.UserDto}

	repo := &mock.RepositoryMock{}
	repo.On("Update", t.User.ID.String(), t.UpdateUser).Return(t.User, nil)

	srv := NewService(repo)
	actual, err := srv.Update(context.Background(), t.UpdateUserReqMock)

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), want, actual)
}

func (t *UserServiceTest) TestUpdateNotFound() {
	repo := &mock.RepositoryMock{}
	repo.On("Update", t.User.ID.String(), t.UpdateUser).Return(nil, errors.New("Not found user"))

	srv := NewService(repo)
	actual, err := srv.Update(context.Background(), t.UpdateUserReqMock)

	st, ok := status.FromError(err)

	assert.True(t.T(), ok)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.NotFound, st.Code())
}

func (t *UserServiceTest) TestDeleteSuccess() {
	want := &proto.DeleteUserResponse{Success: true}

	repo := &mock.RepositoryMock{}
	repo.On("Delete", t.User.ID.String()).Return(nil)

	srv := NewService(repo)
	actual, err := srv.Delete(context.Background(), &proto.DeleteUserRequest{Id: t.UserDto.Id})

	assert.Nil(t.T(), err)
	assert.Equal(t.T(), want, actual)
}

func (t *UserServiceTest) TestDeleteNotFound() {
	repo := &mock.RepositoryMock{}
	repo.On("Delete", t.User.ID.String()).Return(errors.New("Not found user"))

	srv := NewService(repo)
	actual, err := srv.Delete(context.Background(), &proto.DeleteUserRequest{Id: t.UserDto.Id})

	st, ok := status.FromError(err)
	assert.True(t.T(), ok)
	assert.Nil(t.T(), actual)
	assert.Equal(t.T(), codes.NotFound, st.Code())
}
