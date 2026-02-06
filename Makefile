.PHONY: test coverage

test:
	go test -v ./...

coverage: coverage.out
	go tool cover -func=coverage.out

coverage.out:
	go test -coverprofile=coverage.out ./...
