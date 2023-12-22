package repository

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"gorm.io/gorm"
)

type UserRepositoryImpl struct {
	Db *gorm.DB
}

func (r *UserRepositoryImpl) FindAll(user *[]*model.User) error {
	return r.Db.Find(&user).Error
}

func (r *UserRepositoryImpl) FindById(id string, user *model.User) error {
	return r.Db.First(&user, "id = ?", id).Error
}

func (r *UserRepositoryImpl) Create(user *model.User) error {
	return r.Db.Create(&user).Error
}

func (r *UserRepositoryImpl) Update(id string, user *model.User) error {
	return r.Db.Where("id = ?", id).Updates(&user).Error
}

func (r *UserRepositoryImpl) Delete(id string) error {
	return r.Db.Delete(&model.User{}, "id = ?", id).Error
}
