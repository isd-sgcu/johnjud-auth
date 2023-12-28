server:
	go run ./src/.

mock-gen:
	mockgen -source ./src/pkg/repository/cache/cache.repository.go -destination ./src/mocks/repository/cache/cache.mock.go
	mockgen -source ./src/pkg/repository/auth/auth.repository.go -destination ./src/mocks/repository/auth/auth.mock.go

test:
	go vet ./...
	go test  -v -coverpkg ./src/internal/... -coverprofile coverage.out -covermode count ./src/internal/...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o coverage.html