.PHONY: all build test lint format

all: format lint test build

## Build all packages
build:
	go build -o model-validate ./cmd/model-validate

## Run all tests
test:
	go test ./...

## Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## Format source code
format:
	gofmt -w .
