# Base Image
FROM golang:1.21.4-alpine3.18 as base

# Working directory
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o server ./cmd/main.go

# Copy config files
COPY ./config ./config

# Adding the grpc_health_probe
RUN GRPC_HEALTH_PROBE_VERSION=v0.3.1 && \
    wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe

# Create master image
FROM alpine AS master

# Working directory
WORKDIR /app

# Copy grpc_heath_prob
COPY --from=base /bin/grpc_health_probe ./

# Copy execute file
COPY --from=base /app/server ./

# Copy config files
COPY --from=base /app/config ./config

# Set ENV to production
ENV GO_ENV production

# Expose port 3002
EXPOSE 3002

# Run the application
CMD ["./server"]