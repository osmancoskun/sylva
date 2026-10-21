BINARY_CLI := sylva
BINARY_DAEMON := sylvad
BUILD_DIR := bin
GO := go
GOFLAGS :=
DOCKER_COMPOSE := docker compose

.PHONY: all build build-cli build-daemon test vet clean docker-test docker-smoke docker-down

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

docker-test:
	$(DOCKER_COMPOSE) run --rm --build test

docker-smoke:
	$(DOCKER_COMPOSE) up -d --build sylvad
	$(DOCKER_COMPOSE) run --rm --build sylva ping
	$(DOCKER_COMPOSE) down --remove-orphans

docker-down:
	$(DOCKER_COMPOSE) down --remove-orphans

clean:
	rm -rf $(BUILD_DIR)
	$(GO) clean
