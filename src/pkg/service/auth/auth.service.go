package auth

import (
	"github.com/isd-sgcu/johnjud-auth/src/config"
	"github.com/isd-sgcu/johnjud-auth/src/internal/service/auth"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

func NewService(userRepo user.Repository, config config.App) authProto.AuthServiceServer {
	return auth.NewService(userRepo, config)
}
