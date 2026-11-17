# Makefile for the gateway service
DOCKER_IMAGE?=op-gateway
DOCKER_TAG?=latest
DOCKER_CONTAINER_NAME?=gateway
RUST_LOG?=debug
CONTAINER_TOOL?=docker ## CONTAINER_TOOL=nerdctl 

test:
	@cargo test -- --skip test_e2e

fmt:
	@cargo fmt

fmt-check:
	@cargo fmt -- --check

clippy:
	@cargo clippy -- -D warnings

lint: clippy

build:
	@cargo build --release

run: build
	@cargo run --release --bin gateway

docker-build:
	@${CONTAINER_TOOL} build $(if ${RUNTIME_IMAGE},--build-arg RUNTIME_IMAGE=${RUNTIME_IMAGE}) -f Dockerfile -t ${DOCKER_IMAGE}:${DOCKER_TAG} ..

docker-clean:
	@${CONTAINER_TOOL} rm -f ${DOCKER_CONTAINER_NAME} 2> /dev/null

docker-run: docker-clean docker-build
	@${CONTAINER_TOOL} run -p 8080:8080 -e RUST_LOG=${RUST_LOG} -v ./.env:/.env \
		--name ${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE}:${DOCKER_TAG}

help:
	@echo ""
	@echo "Usage: make [vars] <cmd>"
	@echo ""
	@echo "Available commands:"
	@echo "  test            Run unit tests"
	@echo "  fmt             Format code"
	@echo "  fmt-check       Check code formatting"
	@echo "  clippy          Run clippy linter"
	@echo "  lint            Run linters"
	@echo "  build           Build the project"
	@echo "  run             Run the project"
	@echo "  docker-build    Build Docker image"
	@echo "  docker-clean    Clean up Docker container"
	@echo "  docker-run      Run Docker container"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  DOCKER_IMAGE        Name of the Docker image (default: op-gateway)"
	@echo "  DOCKER_TAG          Tag for the Docker image (default: latest)"
	@echo "  DOCKER_CONTAINER_NAME Name of the Docker container (default: gateway)"
	@echo "  RUST_LOG            Log level for Rust (default: debug)"
	@echo "  CONTAINER_TOOL      Tool for managing containers, e.g. nerdctl (default: docker)"
	@echo ""

default: help
