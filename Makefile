server:
	go run ./src/.

mock-gen:
	mockgen -source ./src/pkg/repository/cache/cache.repository.go -destination ./src/mocks/repository/cache/cache.mock.go
	mockgen -source ./src/pkg/repository/auth/auth.repository.go -destination ./src/mocks/repository/auth/auth.mock.go