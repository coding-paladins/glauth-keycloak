# GLAuth and plugin must share one Go/module build (plugin ABI).
FROM golang:1.21-bullseye AS builder

WORKDIR /build
RUN git clone --depth 1 --branch v2.4.0 https://github.com/glauth/glauth.git glauth-repo && \
    rm -f glauth-repo/go.work && \
    mkdir -p glauth-repo/v2/pkg/plugins/glauth-keycloak

COPY keycloak/*.go glauth-repo/v2/pkg/plugins/glauth-keycloak/
RUN sed -i 's/package keycloak/package main/g' glauth-repo/v2/pkg/plugins/glauth-keycloak/*.go && \
    echo '' >> glauth-repo/v2/pkg/plugins/glauth-keycloak/keycloak.go && \
    echo 'func main() {}' >> glauth-repo/v2/pkg/plugins/glauth-keycloak/keycloak.go

# Single module at repo root so replace github.com/glauth/glauth => ... contains v2/pkg/embed
RUN cp glauth-repo/v2/go.mod glauth-repo/go.mod && \
    sed -i 's|module github.com/glauth/glauth/v2|module github.com/glauth/glauth|' glauth-repo/go.mod && \
    rm glauth-repo/v2/go.mod && \
    rm -f glauth-repo/v2/pkg/server/embed_sqlite.go glauth-repo/v2/pkg/server/embed_mysql.go 2>/dev/null; true

WORKDIR /build/glauth-repo
RUN echo 'replace github.com/glauth/glauth => /build/glauth-repo' >> go.mod && \
    echo 'replace github.com/glauth/glauth/v2 => /build/glauth-repo' >> go.mod

ENV GOWORK=off GONOPROXY=github.com/glauth GONOSUMDB=github.com/glauth
RUN go get github.com/go-ldap/ldap/v3@v3.4.6 github.com/go-resty/resty/v2@v2.11.0 golang.org/x/oauth2@v0.18.0 && \
    go mod tidy && go mod download && \
    go build -o /build/glauth ./v2 && \
    go build -buildmode=plugin -o /build/keycloak.so ./v2/pkg/plugins/glauth-keycloak

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/glauth /build/keycloak.so /app/
RUN mkdir -p /app/config
ENTRYPOINT ["/app/glauth"]
CMD ["-c", "/app/config/config.cfg"]
