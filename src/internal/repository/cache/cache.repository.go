package cache

import (
	"context"
	"encoding/json"
	"github.com/redis/go-redis/v9"
	"time"
)

type repositoryImpl struct {
	client *redis.Client
}

func NewRepository(client *redis.Client) *repositoryImpl {
	return &repositoryImpl{client: client}
}

func (r *repositoryImpl) AddSetMember(key string, value interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	v, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.SAdd(ctx, key, v).Err()
}

func (r *repositoryImpl) IsSetMember(key string, value interface{}) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	v, err := json.Marshal(value)
	if err != nil {
		return false, err
	}

	return r.client.SIsMember(ctx, key, v).Result()
}
