BINARY_CLI := sylva
BINARY_DAEMON := sylvad
BUILD_DIR := bin
GO := go
GOFLAGS :=
# Isolated BuildKit cannot resolve proxy.golang.org on this host; classic
# builder honors compose `build.network: host`.
export DOCKER_BUILDKIT := 0
export COMPOSE_BAKE := false
DOCKER_COMPOSE := docker compose
FUZZTIME ?= 10s
BENCHTIME ?= 2s
PROFILE_DIR ?= .profiles
COVERAGE_DIR ?= .coverage

.PHONY: all build build-cli build-daemon test vet check analyze security coverage fuzz bench profile-memory clean docker-test docker-smoke docker-e2e docker-down

all: build

build: build-cli build-daemon

build-cli:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_CLI) ./cmd/sylva

build-daemon:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_DAEMON) ./cmd/sylvad

test:
	$(GO) test -race -count=1 -timeout=5m -cover ./...

vet:
	$(GO) vet ./...

check:
	./scripts/check.sh

analyze:
	./scripts/check.sh analysis

security:
	./scripts/check.sh security

coverage:
	@mkdir -p "$(COVERAGE_DIR)"
	@status=0; \
	rm -f "$(COVERAGE_DIR)/coverage.out" "$(COVERAGE_DIR)/coverage.txt" "$(COVERAGE_DIR)/coverage.html"; \
	$(GO) test -race -count=1 -timeout=5m -covermode=atomic -coverprofile="$(COVERAGE_DIR)/coverage.out" ./... || status=$$?; \
	if [ -s "$(COVERAGE_DIR)/coverage.out" ]; then \
		$(GO) tool cover -func="$(COVERAGE_DIR)/coverage.out" > "$(COVERAGE_DIR)/coverage.txt" || status=1; \
		$(GO) tool cover -html="$(COVERAGE_DIR)/coverage.out" -o "$(COVERAGE_DIR)/coverage.html" || status=1; \
	else \
		status=1; \
	fi; \
	exit $$status

fuzz:
	$(GO) test -run '^$$' -fuzz '^FuzzEncryptDecrypt$$' -fuzztime=$(FUZZTIME) -parallel=2 -timeout=5m ./internal/crypto
	$(GO) test -run '^$$' -fuzz '^FuzzDecryptMalformedEnvelope$$' -fuzztime=$(FUZZTIME) -parallel=2 -timeout=5m ./internal/crypto

bench:
	$(GO) test -run '^$$' -bench 'Benchmark(VaultRoundTrip|ClipboardLifecycle)$$' -benchmem -benchtime=$(BENCHTIME) -count=1 -timeout=5m ./internal/vault ./internal/clipboard

profile-memory:
	@mkdir -p "$(PROFILE_DIR)"
	$(GO) test -run '^$$' -bench '^BenchmarkVaultRoundTrip$$' -benchmem -benchtime=$(BENCHTIME) -count=1 -timeout=5m -memprofilerate=1 -memprofile="$(PROFILE_DIR)/vault.heap" -o "$(PROFILE_DIR)/vault.test" ./internal/vault
	$(GO) test -run '^$$' -bench '^BenchmarkClipboardLifecycle$$' -benchmem -benchtime=$(BENCHTIME) -count=1 -timeout=5m -memprofilerate=1 -memprofile="$(PROFILE_DIR)/clipboard.heap" -o "$(PROFILE_DIR)/clipboard.test" ./internal/clipboard

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
	$(DOCKER_COMPOSE) run --rm --no-deps sylva init --non-interactive
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

docker-e2e:
	python3 scripts/docker_e2e.py

docker-down:
	$(DOCKER_COMPOSE) down --remove-orphans --volumes

clean:
	rm -rf $(BUILD_DIR)
	$(GO) clean
