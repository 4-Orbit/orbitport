# syntax=docker/dockerfile:1

################################################################################

ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.24
# Runtime base. The default needs a dhi.io (Docker Hardened Images) login; set
# RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot to build without one.
ARG RUNTIME_IMAGE=dhi.io/static:20250419-debian13

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

ARG BUILD_TARGET=plugin

WORKDIR /app

# Copy go mod and sum files for downloading deps
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o bin/ ./cmd/${BUILD_TARGET}/...

################################################################################

# distroless: CA certs and a nonroot user, no shell or package manager
FROM ${RUNTIME_IMAGE}

ARG BUILD_TARGET=plugin

COPY --from=builder /app/bin/${BUILD_TARGET} /app

USER 65532:65532

ENTRYPOINT ["/app"]
