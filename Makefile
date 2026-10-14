BINARY_NAME=ambicert
BIN_DIR=bin
VERSION=$(shell git describe --tags --always || echo "dev")
BUILD_TIME=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}"

PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all clean build build-all lint vulncheck test cover-html help

all: clean lint test build

help:
	@echo "Использование: make <target>"
	@echo "Targets:"
	@echo "  lint         - Запуск golangci-lint"
	@echo "  vulncheck    - Проверка уязвимостей (govulncheck)"
	@echo "  test         - Запуск тестов с проверкой покрытия"
	@echo "  cover-html   - Открыть отчет о покрытии в браузере"
	@echo "  build        - Сборка бинарника под текущую систему"
	@echo "  build-all    - Кросс-компиляция под все платформы"
	@echo "  clean        - Удаление скомпилированных файлов"

lint:
	@echo "==> Running lint..."
	@if ! command -v golangci-lint >/dev/null; then \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -u -b $(go env GOPATH)/bin v1.61.0; \
	fi
	golangci-lint run ./...

vulncheck:
	@echo "==> Running govulncheck..."
	@if ! command -v govulncheck >/dev/null; then \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
	fi
	govulncheck ./...

test:
	@echo "==> Running tests..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

cover-html: test
	go tool cover -html=coverage.out

build:
	@echo "==> Building for current OS..."
	go mod tidy
	go build ${LDFLAGS} -o $(BIN_DIR)/$(BINARY_NAME) main.go

build-all: clean
	@echo "==> Cross-compiling for all platforms..."
	@$(foreach PLATFORM,$(PLATFORMS), \
		OS=$(word 1,$(subst /, ,$(PLATFORM))); \
		ARCH=$(word 2,$(subst /, ,$(PLATFORM))); \
		EXT=$$( [ "$$OS" = "windows" ] && echo ".exe" || echo "" ); \
		echo "    Building $$OS/$$ARCH..."; \
		GOOS=$$OS GOARCH=$$ARCH go build ${LDFLAGS} -o $(BIN_DIR)/$(BINARY_NAME)-$$OS-$$ARCH$$EXT main.go; \
	)

clean:
	@echo "==> Cleaning..."
	rm -rf $(BIN_DIR)
	rm -f coverage.out
