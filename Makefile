server:
	. ./tools/export-env.sh ; go run ./cmd/.

mock-gen:
	mockgen -source ./pkg/repository/cache/cache.repository.go -destination ./mocks/repository/cache/cache.mock.go
	mockgen -source ./pkg/repository/auth/auth.repository.go -destination ./mocks/repository/auth/auth.mock.go

test:
	go vet ./...
	go test  -v -coverpkg ./internal/... -coverprofile coverage.out -covermode count ./internal/...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o coverage.html

proto:
	go get github.com/isd-sgcu/johnjud-go-proto@latest