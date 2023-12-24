package user

import (
	"context"

	"github.com/isd-sgcu/johnjud-auth/src/internal/domain/model"
	userRepo "github.com/isd-sgcu/johnjud-auth/src/pkg/repository/user"
	proto "github.com/isd-sgcu/johnjud-go-proto/johnjud/auth/user/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type serviceImpl struct {
	proto.UnimplementedUserServiceServer
	repo userRepo.Repository
}

func NewService(repo userRepo.Repository) *serviceImpl {
	return &serviceImpl{repo: repo}
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
	raw := &model.User{
		Email:     request.Email,
		Password:  request.Password,
		Firstname: request.Firstname,
		Lastname:  request.Lastname,
	}

	err := s.repo.Update(request.Id, raw)
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &proto.UpdateUserResponse{User: RawToDto(raw)}, nil
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
		Password:  in.Password,
		Firstname: in.Firstname,
		Lastname:  in.Lastname,
		Role:      string(in.Role),
	}
}
