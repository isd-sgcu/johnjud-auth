package cache

import (
	"github.com/isd-sgcu/johnjud-auth/src/internal/repository/cache"
	"github.com/redis/go-redis/v9"
)

type Repository interface {
	SetValue(key string, value interface{}, ttl int) error
	GetValue(key string, value interface{}) error
	AddSetMember(key string, value interface{}) error
	IsSetMember(key string, value interface{}) (bool, error)
}

func NewRepository(client *redis.Client) Repository {
	return cache.NewRepository(client)
}