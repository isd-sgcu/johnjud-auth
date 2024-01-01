package cache

type Repository interface {
	SetValue(key string, value interface{}, ttl int) error
	GetValue(key string, value interface{}) error
	DeleteValue(key string) error
}
