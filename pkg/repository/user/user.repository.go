package user

import (
	"github.com/isd-sgcu/johnjud-auth/internal/domain/model"
)

type Repository interface {
	FindAll(user *[]*model.User) error
	FindById(id string, user *model.User) error
	FindByEmail(email string, user *model.User) error
	Create(user *model.User) error
	Update(id string, user *model.User) error
	Delete(id string) error
}
