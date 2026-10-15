BINARY_NAME=ambicert
BIN_DIR=bin
VERSION ?= $(shell git describe --tags --always --dirty || echo "dev")
LDFLAGS=-ldflags "-X main.version=${VERSION}"

PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all clean build build-all lint vulncheck test cover-html

all: clean lint test build

lint:
	@echo "==> Running golangci-lint..."
	golangci-lint run ./...

vulncheck:
	@echo "==> Running govulncheck..."
	govulncheck ./...

test:
	@echo "==> Running tests..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

cover-html: test
	go tool cover -html=coverage.out -o coverage.html
	@echo "Отчет создан: coverage.html"

build:
	go build ${LDFLAGS} -o $(BIN_DIR)/$(BINARY_NAME) main.go

build-all: clean
	@$(foreach PLATFORM,$(PLATFORMS), \
		OS=$(word 1,$(subst /, ,$(PLATFORM))); \
		ARCH=$(word 2,$(subst /, ,$(PLATFORM))); \
		EXT=$$( [ "$$OS" = "windows" ] && echo ".exe" || echo "" ); \
		GOOS=$$OS GOARCH=$$ARCH go build ${LDFLAGS} -o $(BIN_DIR)/$(BINARY_NAME)-$$OS-$$ARCH$$EXT main.go; \
	)

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html

