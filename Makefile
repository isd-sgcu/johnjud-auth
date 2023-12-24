server:
	go run ./src/.

test:
	go vet ./...
	go test  -v -coverpkg ./src/internal/... -coverprofile coverage.out -covermode count ./src/internal/...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o coverage.html