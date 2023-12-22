package repository

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/src/internal/repository"
	"gorm.io/gorm"
)

type UserRepository interface {
	FindAll(user *[]*model.User) error
	FindById(id string, user *model.User) error
	Create(user *model.User) error
	Update(id string, user *model.User) error
	Delete(id string) error
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return repository.NewUserRepository(db)
}
