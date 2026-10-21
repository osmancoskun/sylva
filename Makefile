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
	$(DOCKER_COMPOSE) run --rm --no-deps sylva set company.com company-secret
	$(DOCKER_COMPOSE) run --rm --no-deps sylva set mail.company.com --inherit
	$(DOCKER_COMPOSE) run --rm --no-deps sylva get mail.company.com
	$(DOCKER_COMPOSE) run --rm --no-deps sylva set github-token tokensecret
	$(DOCKER_COMPOSE) run --rm --no-deps sylva get github-token
	$(DOCKER_COMPOSE) run --rm --no-deps sylva set SYLVA_EXAMPLE envsecret env
	$(DOCKER_COMPOSE) run --rm --no-deps sylva get SYLVA_EXAMPLE env
	$(DOCKER_COMPOSE) run --rm --no-deps sylva set 10.0.0.1 sshsecret ssh
	$(DOCKER_COMPOSE) run --rm --no-deps sylva get 10.0.0.1 ssh
	$(DOCKER_COMPOSE) run --rm --no-deps sylva list
	$(DOCKER_COMPOSE) run --rm --no-deps sylva update github-token tokensecret2
	$(DOCKER_COMPOSE) run --rm --no-deps sylva get github-token
	$(DOCKER_COMPOSE) run --rm --no-deps sylva delete github-token --yes
	$(DOCKER_COMPOSE) down --remove-orphans

docker-down:
	$(DOCKER_COMPOSE) down --remove-orphans --volumes

clean:
	rm -rf $(BUILD_DIR)
	$(GO) clean
