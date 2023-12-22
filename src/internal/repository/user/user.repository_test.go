package user

import (
	"fmt"
	"github.com/go-faker/faker/v4"
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"testing"
)

type UserRepositoryTest struct {
	suite.Suite
	db          *gorm.DB
	userRepo    *repositoryImpl
	initialUser *model.User
}

func TestUserRepository(t *testing.T) {
	suite.Run(t, new(UserRepositoryTest))
}

func (t *UserRepositoryTest) SetupTest() {
	dsn := "file:memory:?cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	assert.NoError(t.T(), err)

	_ = db.Migrator().DropTable(&model.User{})

	err = db.AutoMigrate(&model.User{})
	assert.NoError(t.T(), err)

	userRepository := &repositoryImpl{Db: db}

	initialUser := &model.User{
		Email:        faker.Email(),
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: faker.Word(),
	}
	err = userRepository.Create(initialUser)
	assert.NoError(t.T(), err)

	t.db = db
	t.userRepo = userRepository
	t.initialUser = initialUser

	fmt.Println("Setup Test Finished")
}

func (t *UserRepositoryTest) TestFindAllSuccess() {
	var users []*model.User
	err := t.userRepo.FindAll(&users)
	assert.NoError(t.T(), err)
	assert.NotEmpty(t.T(), users)
}

func (t *UserRepositoryTest) TestFindByIdSuccess() {
	var user model.User
	err := t.userRepo.FindById(t.initialUser.ID.String(), &user)
	assert.NoError(t.T(), err)
	assert.Equal(t.T(), t.initialUser.ID, user.ID)
}

func (t *UserRepositoryTest) TestFindByIdNotFound() {
	notFoundId := faker.UUIDDigit()

	var user *model.User
	err := t.userRepo.FindById(notFoundId, user)
	assert.Equal(t.T(), gorm.ErrRecordNotFound, err)
}

func (t *UserRepositoryTest) TestCreateSuccess() {
	createUser := &model.User{
		Email:        faker.Email(),
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: faker.Word(),
	}

	err := t.userRepo.Create(createUser)
	assert.NoError(t.T(), err)
}

func (t *UserRepositoryTest) TestCreateDuplicateEmail() {
	createUser := &model.User{
		Email:        t.initialUser.Email,
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: faker.Word(),
	}

	err := t.userRepo.Create(createUser)
	assert.Error(t.T(), err)
}

func (t *UserRepositoryTest) TestUpdateSuccess() {
	updateUser := &model.User{
		Email:        faker.Email(),
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: faker.Word(),
	}

	err := t.userRepo.Update(t.initialUser.ID.String(), updateUser)
	assert.NoError(t.T(), err)
}

func (t *UserRepositoryTest) TestUpdateDuplicateEmail() {
	createUser := &model.User{
		Email:        faker.Email(),
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: faker.Word(),
	}

	err := t.userRepo.Create(createUser)
	assert.NoError(t.T(), err)

	updateUser := &model.User{
		Email:        createUser.Email,
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: faker.Word(),
	}

	err = t.userRepo.Update(t.initialUser.ID.String(), updateUser)
	assert.Error(t.T(), err)
}

func (t *UserRepositoryTest) TestDeleteSuccess() {
	createUser := &model.User{
		Email:        faker.Email(),
		Password:     faker.Password(),
		Firstname:    faker.FirstName(),
		Lastname:     faker.LastName(),
		Role:         constant.USER,
		RefreshToken: faker.Word(),
	}

	err := t.userRepo.Create(createUser)
	assert.NoError(t.T(), err)

	err = t.userRepo.Delete(createUser.ID.String())
	assert.NoError(t.T(), err)
}

func (t *UserRepositoryTest) TestDeleteNotFound() {
	notFoundId := faker.UUIDDigit()
	err := t.userRepo.Delete(notFoundId)
	assert.NoError(t.T(), err)
}
