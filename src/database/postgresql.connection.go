package database

import (
	"fmt"
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
	"strconv"
)

func InitPostgresDatabase(conf *config.Database, isDebug bool) (db *gorm.DB, err error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", conf.Host, strconv.Itoa(conf.Port), conf.Username, conf.Password, conf.Name, conf.SSL)

	gormConf := &gorm.Config{TranslateError: true}

	if !isDebug {
		gormConf.Logger = gormLogger.Default.LogMode(gormLogger.Silent)
	}

	db, err = gorm.Open(postgres.Open(dsn), gormConf)
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(&model.User{})
	if err != nil {
		return nil, err
	}

	return
}
