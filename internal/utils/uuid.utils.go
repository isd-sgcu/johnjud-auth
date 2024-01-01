package utils

import "github.com/google/uuid"

type IUuidUtil interface {
	GetNewUUID() *uuid.UUID
}

type uuidUtil struct{}

func NewUuidUtil() *uuidUtil {
	return &uuidUtil{}
}

func (u *uuidUtil) GetNewUUID() *uuid.UUID {
	uuid := uuid.New()
	return &uuid
}
