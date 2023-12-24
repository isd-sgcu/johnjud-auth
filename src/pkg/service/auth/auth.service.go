package auth

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/service/auth"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/token"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

func NewService(userRepo user.Repository, tokenService token.Service, bcryptUtil utils.IBcryptUtil) authProto.AuthServiceServer {
	return auth.NewService(userRepo, tokenService, bcryptUtil)
}
