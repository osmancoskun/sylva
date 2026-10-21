ARG GO_IMAGE=golang:1.26-alpine
ARG RUNTIME_IMAGE=alpine:3.21

# Stage 1: Base toolchain and module cache
FROM ${GO_IMAGE} AS base
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Stage 2: Isolated test and verification runner
FROM base AS test
CMD ["sh", "-c", "go vet ./... && go test -v -cover ./..."]

# Stage 3: Builder for sylva and sylvad binaries
FROM base AS builder
RUN CGO_ENABLED=0 go build -o /out/sylva ./cmd/sylva && \
    CGO_ENABLED=0 go build -o /out/sylvad ./cmd/sylvad

# Stage 4: Minimal sylvad server container
FROM ${RUNTIME_IMAGE} AS sylvad
WORKDIR /app
COPY --from=builder /out/sylvad /usr/local/bin/sylvad
ENTRYPOINT ["sylvad"]

# Stage 5: Minimal sylva CLI client container
FROM ${RUNTIME_IMAGE} AS sylva
WORKDIR /app
COPY --from=builder /out/sylva /usr/local/bin/sylva
ENTRYPOINT ["sylva"]
