package auth

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"testing"
)

type AuthRepositoryTest struct {
	suite.Suite
	db       *gorm.DB
	authRepo *repositoryImpl
}

func TestAuthRepository(t *testing.T) {
	suite.Run(t, new(AuthRepositoryTest))
}

func (t *AuthRepositoryTest) SetupTest() {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", "localhost", "5433", "root", "root", "johnjud_test_db", "")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true})

	assert.NoError(t.T(), err)

	_ = db.Migrator().DropTable(&model.User{})
	_ = db.Migrator().DropTable(&model.AuthSession{})

	err = db.AutoMigrate(&model.User{}, &model.AuthSession{})
	assert.NoError(t.T(), err)

	authRepo := NewRepository(db)

	t.db = db
	t.authRepo = authRepo
}

func (t *AuthRepositoryTest) TestCreateSuccess() {
	createAuthSession := &model.AuthSession{
		UserID: uuid.New(),
	}

	err := t.authRepo.Create(createAuthSession)
	assert.Nil(t.T(), err)
}

func (t *AuthRepositoryTest) TestDeleteSuccess() {
	createAuthSession := &model.AuthSession{
		UserID: uuid.New(),
	}

	err := t.authRepo.Create(createAuthSession)
	assert.Nil(t.T(), err)

	err = t.authRepo.Delete(createAuthSession.ID.String())
	assert.Nil(t.T(), err)
}
