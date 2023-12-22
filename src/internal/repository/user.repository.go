package repository

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"gorm.io/gorm"
)

type userRepositoryImpl struct {
	Db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *userRepositoryImpl {
	return &userRepositoryImpl{Db: db}
}

func (r *userRepositoryImpl) FindAll(user *[]*model.User) error {
	return r.Db.Find(&user).Error
}

func (r *userRepositoryImpl) FindById(id string, user *model.User) error {
	return r.Db.First(&user, "id = ?", id).Error
}

func (r *userRepositoryImpl) Create(user *model.User) error {
	return r.Db.Create(&user).Error
}

func (r *userRepositoryImpl) Update(id string, user *model.User) error {
	return r.Db.Where("id = ?", id).Updates(&user).Error
}

func (r *userRepositoryImpl) Delete(id string) error {
	return r.Db.Delete(&model.User{}, "id = ?", id).Error
}
