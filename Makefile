# Run the application
.PHONY: help build run test clean lint fmt vet install dev deps vendor tidy

# Variables
BINARY_NAME=watchr
MAIN_PATH=./cmd/watchr/main.go
BUILD_DIR=./bin
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-s -w"

# Default target
help:
	@echo "Available targets:"
	@echo "  build        - Build the application"
	@echo "  run          - Run the application"
	@echo "  test         - Run tests"
	@echo "  test-cover   - Run tests with coverage"
	@echo "  clean        - Remove build artifacts"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  vet          - Run go vet"
	@echo "  install      - Install the binary"
	@echo "  dev          - Run in development mode with auto-reload"
	@echo "  deps         - Download dependencies"
	@echo "  vendor       - Vendor dependencies"
	@echo "  tidy         - Tidy and verify dependencies"

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)

run: build
	@echo "Running $(BINARY_NAME)..."
	@$(BUILD_DIR)/$(BINARY_NAME)

# Run tests
test:
	@echo "Running tests..."
	$(GO) test $(GOFLAGS) ./...

# Run tests with coverage
test-cover:
	@echo "Running tests with coverage..."
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(BINARY_NAME) coverage.out coverage.html
	@$(GO) clean

# Run linter (requires golangci-lint)
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest" && exit 1)
	@mkdir -p $(CURDIR)/.cache/golangci-lint
	GOLANGCI_LINT_CACHE=$(CURDIR)/.cache/golangci-lint GOCACHE=$(CURDIR)/.cache golangci-lint run ./...

# Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...

# Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download

# Vendor dependencies
vendor:
	@echo "Vendoring dependencies..."
	$(GO) mod vendor

# Tidy and verify dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GO) mod tidy
	$(GO) mod verify

# Full check before commit
check: fmt vet lint test
	@echo "All checks passed!"
