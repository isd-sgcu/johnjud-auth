package token

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	tokenDto "github.com/isd-sgcu/johnjud-auth/src/internal/domain/dto/token"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	"github.com/isd-sgcu/johnjud-auth/src/pkg/service/jwt"
	authProto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/auth/v1"
)

type serviceImpl struct {
	jwtService jwt.Service
	uuidUtil   utils.IUuidUtil
}

func NewService(jwtService jwt.Service, uuidUtil utils.IUuidUtil) *serviceImpl {
	return &serviceImpl{jwtService: jwtService, uuidUtil: uuidUtil}
}

func (s *serviceImpl) CreateCredential(userId string, role constant.Role) (*authProto.Credential, error) {
	return nil, nil
}

func (s *serviceImpl) Validate(token string) (*tokenDto.UserCredential, error) {
	return nil, nil
}

func (s *serviceImpl) CreateRefreshToken() string {
	return s.uuidUtil.GetNewUUID().String()
}
