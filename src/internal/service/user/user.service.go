package user

import (
	"context"

	"github.com/isd-sgcu/johnjud-auth/src/internal/constant"
	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	"github.com/isd-sgcu/johnjud-auth/src/internal/utils"
	userRepo "github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	proto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/user/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serviceImpl struct {
	proto.UnimplementedUserServiceServer
	repo       userRepo.Repository
	bcryptUtil utils.IBcryptUtil
}

func NewService(repo userRepo.Repository, bcryptUtil utils.IBcryptUtil) *serviceImpl {
	return &serviceImpl{repo: repo, bcryptUtil: bcryptUtil}
}

func (s *serviceImpl) FindOne(_ context.Context, request *proto.FindOneUserRequest) (*proto.FindOneUserResponse, error) {
	raw := model.User{}

	err := s.repo.FindById(request.Id, &raw)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &proto.FindOneUserResponse{User: RawToDto(&raw)}, nil
}

func (s *serviceImpl) Update(_ context.Context, request *proto.UpdateUserRequest) (*proto.UpdateUserResponse, error) {
	hashPassword, err := s.bcryptUtil.GenerateHashedPassword(request.Password)
	if err != nil {
		return nil, status.Error(codes.Internal, constant.InternalServerErrorMessage)
	}

	updateUser := &model.User{
		Email:     request.Email,
		Password:  hashPassword,
		Firstname: request.Firstname,
		Lastname:  request.Lastname,
	}

	err = s.repo.Update(request.Id, updateUser)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &proto.UpdateUserResponse{User: RawToDto(updateUser)}, nil
}

func (s *serviceImpl) Delete(_ context.Context, request *proto.DeleteUserRequest) (*proto.DeleteUserResponse, error) {
	err := s.repo.Delete(request.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "something wrong when deleting user")
	}

	return &proto.DeleteUserResponse{Success: true}, nil
}

func RawToDto(in *model.User) *proto.User {
	return &proto.User{
		Id:        in.ID.String(),
		Email:     in.Email,
		Firstname: in.Firstname,
		Lastname:  in.Lastname,
		Role:      string(in.Role),
	}
}
