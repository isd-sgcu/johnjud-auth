package user

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/src/internal/repository/user"
	"gorm.io/gorm"
)

type Repository interface {
	FindAll(user *[]*model.User) error
	FindById(id string, user *model.User) error
	FindByEmail(email string, user *model.User) error
	Create(user *model.User) error
	Update(id string, user *model.User) error
	Delete(id string) error
}

func NewRepository(db *gorm.DB) Repository {
	return user.NewRepository(db)
}
