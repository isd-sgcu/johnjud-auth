server:
	go run ./src/.

mock-gen:
	mockgen -source ./src/pkg/repository/cache/cache.repository.go -destination ./src/mocks/repository/cache/cache.mock.go