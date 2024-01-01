package auth

import (
	"github.com/isd-sgcu/johnjud-auth/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/internal/repository/auth"
	"gorm.io/gorm"
)

type Repository interface {
	Create(auth *model.AuthSession) error
	Delete(id string) error
}

func NewRepository(db *gorm.DB) Repository {
	return auth.NewRepository(db)
}
