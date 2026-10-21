BINARY_CLI := sylva
BINARY_DAEMON := sylvad
BUILD_DIR := bin
GO := go
GOFLAGS :=
DOCKER_COMPOSE := docker compose

.PHONY: all build build-cli build-daemon test vet check clean docker-test docker-smoke docker-down

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

check:
	./scripts/check.sh

docker-test:
	$(DOCKER_COMPOSE) run --rm --build test

docker-smoke:
	$(DOCKER_COMPOSE) up -d --build sylvad
	@n=0; \
	until $(DOCKER_COMPOSE) run --rm --no-deps --build sylva ping; do \
		n=$$((n+1)); \
		if [ $$n -ge 20 ]; then echo "sylvad did not become ready"; exit 1; fi; \
		sleep 0.3; \
	done
	$(DOCKER_COMPOSE) run --rm --no-deps sylva init
	$(DOCKER_COMPOSE) run --rm --no-deps sylva login set company.com --username osman --password company-secret
	$(DOCKER_COMPOSE) run --rm --no-deps sylva login set mail.company.com --username osman --inherit
	$(DOCKER_COMPOSE) run --rm --no-deps sylva login get mail.company.com --reveal
	$(DOCKER_COMPOSE) run --rm --no-deps sylva cp mail.company.com
	$(DOCKER_COMPOSE) down --remove-orphans

docker-down:
	$(DOCKER_COMPOSE) down --remove-orphans --volumes

clean:
	rm -rf $(BUILD_DIR)
	$(GO) clean
