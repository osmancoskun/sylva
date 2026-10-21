BINARY_CLI := sylva
BINARY_DAEMON := sylvad
BUILD_DIR := bin
GO := go
GOFLAGS :=

.PHONY: all build build-cli build-daemon test lint clean

all: build

build: build-cli build-daemon

build-cli:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_CLI) ./cmd/sylva

build-daemon:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_DAEMON) ./cmd/sylvad

test:
	$(GO) test -race -cover ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf $(BUILD_DIR)
	$(GO) clean
