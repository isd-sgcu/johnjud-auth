package repository

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"testing"
)

type UserRepositoryTest struct {
	suite.Suite
	db       *gorm.DB
	userRepo *UserRepositoryImpl
}

func TestUserRepository(t *testing.T) {
	suite.Run(t, new(UserRepositoryTest))
}

func (t *UserRepositoryTest) SetupTest() {
	db, err := gorm.Open(sqlite.Open("file:memory:?cache=shared"), &gorm.Config{})
	assert.NoError(t.T(), err)

	_ = db.Migrator().DropTable(&model.User{})

	err = db.AutoMigrate(&model.User{})
	assert.NoError(t.T(), err)

	authRepository := &UserRepositoryImpl{Db: db}

	t.db = db
	t.userRepo = authRepository
}

func (t *UserRepositoryTest) TestFindAllSuccess() {

}

func (t *UserRepositoryTest) TestFindByIdSuccess() {

}

func (t *UserRepositoryTest) TestFindByIdNotFound() {

}

func (t *UserRepositoryTest) TestCreateSuccess() {

}

func (t *UserRepositoryTest) TestCreateDuplicateEmail() {

}

func (t *UserRepositoryTest) TestUpdateSuccess() {

}

func (t *UserRepositoryTest) TestUpdateNotFound() {

}

func (t *UserRepositoryTest) TestUpdateDuplicateEmail() {

}

func (t *UserRepositoryTest) TestDeleteSuccess() {

}

func (t *UserRepositoryTest) TestDeleteNotFound() {

}
