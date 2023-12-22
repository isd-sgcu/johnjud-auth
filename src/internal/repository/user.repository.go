package repository

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"gorm.io/gorm"
)

type UserRepositoryImpl struct {
	Db *gorm.DB
}

func (r *UserRepositoryImpl) FindAll(user *[]*model.User) error {
	return nil
}

func (r *UserRepositoryImpl) FindById(id string, user *model.User) error {
	return nil
}

func (r *UserRepositoryImpl) Create(user *model.User) error {
	return nil
}

func (r *UserRepositoryImpl) Update(id string, user *model.User) error {
	return nil
}

func (r *UserRepositoryImpl) Delete(id string) error {
	return nil
}
