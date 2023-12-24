package user

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/stretchr/testify/mock"
)

type RepositoryMock struct {
	mock.Mock
}

func (r *RepositoryMock) FindAll(in *[]*model.User) error {
	args := r.Called(in)

	if args.Get(0) != nil {
		*in = *args.Get(0).(*[]*model.User)
	}

	return args.Error(1)
}

func (r *RepositoryMock) FindById(id string, result *model.User) error {
	args := r.Called(id, result)

	if args.Get(0) != nil {
		*result = *args.Get(0).(*model.User)
	}

	return args.Error(1)
}

func (r *RepositoryMock) Create(in *model.User) error {
	args := r.Called(in)

	if args.Get(0) != nil {
		*in = *args.Get(0).(*model.User)
	}

	return args.Error(1)
}

func (r *RepositoryMock) Update(id string, result *model.User) error {
	args := r.Called(id, result)

	if args.Get(0) != nil {
		*result = *args.Get(0).(*model.User)
	}

	return args.Error(1)
}

func (r *RepositoryMock) Delete(id string) error {
	args := r.Called(id)

	return args.Error(0)
}
