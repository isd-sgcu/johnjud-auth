# Johnjud-auth

Johnjud-auth is a user authentication and authorization service for the Johnjud project.

### What is Johnjud?
Johnjud is a pet adoption web application of the [CUVET For Animal Welfare Club](https://www.facebook.com/CUVETforAnimalWelfareClub)

## Stacks
- golang
- gRPC
- postgresql
- redis

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites
- golang 1.21 or [later](https://go.dev)
- docker
- makefile

### Installing
1. Clone the project from [Goland Backend](https://github.com/isd-sgcu/johnjud-auth)
2. Import project
3. Copy `config.example.yaml` in `config` and paste it in the same location then remove `.example` from its name.
4. Download dependencies by `go mod download`

### Running
1. Run `docker-compose up -d`
2. Run `go run ./cmd/.` or `make server`

### Testing
1. Run `go test  -v -coverpkg ./internal/... -coverprofile coverage.out -covermode count ./internal/...` or `make test`

## Other microservices/repositories of Johnjud
- [Johnjud-gateway](https://github.com/isd-sgcu/johnjud-gateway): Routing and request handling
- [Johnjud-auth](https://github.com/isd-sgcu/johnjud-auth): Authentication and authorization
- [Johnjud-backend](https://github.com/isd-sgcu/johnjud-backend): Main business logic
- [Johnjud-file](https://github.com/isd-sgcu/johnjud-file): File management service
- [Johnjud-proto](https://github.com/isd-sgcu/johnjud-proto): Protobuf files generator
- [Johnjud-go-proto](https://github.com/isd-sgcu/johnjud-go-proto): Generated protobuf files for golang
- [Johnjud-frontend](https://github.com/isd-sgcu/johnjud-frontend): Frontend web application
