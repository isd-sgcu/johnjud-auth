package auth

import (
	"github.com/isd-sgcu/johnjud-auth/internal/service/auth"
	"github.com/isd-sgcu/johnjud-auth/internal/utils"
	authRp "github.com/isd-sgcu/johnjud-auth/pkg/repository/auth"
	userRp "github.com/isd-sgcu/johnjud-auth/pkg/repository/user"
	tokenSvc "github.com/isd-sgcu/johnjud-auth/pkg/service/token"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

func NewService(authRepo authRp.Repository, userRepo userRp.Repository, tokenService tokenSvc.Service, bcryptUtil utils.IBcryptUtil) authProto.AuthServiceServer {
	return auth.NewService(authRepo, userRepo, tokenService, bcryptUtil)
}
