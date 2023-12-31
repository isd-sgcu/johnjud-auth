package user

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/service/user"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	userRepo "github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	userProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/user/v1"
)

func NewService(userRepository userRepo.Repository, bcryptUtil utils.IBcryptUtil) userProto.UserServiceServer {
	return user.NewService(userRepository, bcryptUtil)
}
