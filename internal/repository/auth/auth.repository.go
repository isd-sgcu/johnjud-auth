package auth

import (
	"github.com/isd-sgcu/johnjud-auth/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/pkg/repository/auth"
	"gorm.io/gorm"
)

type repositoryImpl struct {
	Db *gorm.DB
}

func NewRepository(db *gorm.DB) auth.Repository {
	return &repositoryImpl{Db: db}
}

func (r *repositoryImpl) Create(auth *model.AuthSession) error {
	return r.Db.Create(auth).Error
}

func (r *repositoryImpl) Delete(id string) error {
	return r.Db.Delete(&model.AuthSession{}, "id = ?", id).Error
}
