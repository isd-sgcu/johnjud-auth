package auth

import (
	"github.com/isd-sgcu/johnjud-auth/internal/domain/model"
)

type Repository interface {
	Create(auth *model.AuthSession) error
	Delete(id string) error
}
