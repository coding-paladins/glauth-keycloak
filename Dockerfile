# Stage 1: Build the plugin
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Copy go module files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY keycloak.go ./

# Build the plugin as a shared object
# Note: Go plugins require -buildmode=plugin
RUN go build -buildmode=plugin -o keycloak.so keycloak.go

# Stage 2: Create final image with GLAuth and the plugin
FROM glauth/glauth:latest

# Copy the compiled plugin
COPY --from=builder /build/keycloak.so /app/plugins/keycloak.so

# GLAuth will be configured via ConfigMap and run with the plugin
