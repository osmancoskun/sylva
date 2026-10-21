ARG GO_IMAGE=golang:1.26-alpine
ARG TEST_IMAGE=golang:1.26
ARG RUNTIME_IMAGE=alpine:3.21

# Stage 1: Base toolchain and module cache (alpine, used to produce static binaries)
FROM ${GO_IMAGE} AS base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Stage 2: Isolated analysis + race detector (glibc image; alpine/musl cannot race)
FROM ${TEST_IMAGE} AS test
ARG GOTOOLCHAIN=auto
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN chmod +x scripts/check.sh && go install tool && go tool govulncheck ./...
ENV SYLVA_SKIP_GOVULNCHECK=true
CMD ["./scripts/check.sh"]

# Stage 3: Builder for sylva and sylvad binaries
FROM base AS builder
RUN CGO_ENABLED=0 go build -o /out/sylva ./cmd/sylva && \
    CGO_ENABLED=0 go build -o /out/sylvad ./cmd/sylvad

# Stage 4: Minimal sylvad server container
FROM ${RUNTIME_IMAGE} AS sylvad
WORKDIR /data
VOLUME /data
COPY --from=builder /out/sylvad /usr/local/bin/sylvad
ENTRYPOINT ["sylvad"]

# Stage 5: Minimal sylva CLI client container
FROM ${RUNTIME_IMAGE} AS sylva
WORKDIR /tmp
COPY --from=builder /out/sylva /usr/local/bin/sylva
ENTRYPOINT ["sylva"]
