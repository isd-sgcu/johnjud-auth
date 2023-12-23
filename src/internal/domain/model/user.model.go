package model

import "github.com/isd-sgcu/johnjud-auth/src/internal/constant"

type User struct {
	Base
	Email        string        `json:"email" gorm:"type:tinytext;unique"`
	Password     string        `json:"password" gorm:"type:tinytext"`
	Firstname    string        `json:"firstname" gorm:"type:tinytext"`
	Lastname     string        `json:"lastname" gorm:"type:tinytext"`
	Role         constant.Role `json:"role" gorm:"type:tinytext"`
	RefreshToken string        `json:"refresh_token" gorm:"index"`
}
