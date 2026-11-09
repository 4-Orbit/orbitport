ENV_FILE?=".dev.env"
E2E_PROFILE?=happy
CONTAINER_TOOL?=docker ## CONTAINER_TOOL=nerdctl
DOCKER_TAG?=latest ## DOCKER_TAG=v*.*.*

protoc:
	@cd plugins && make protoc

test:
	@cd plugins && make test
	@cd gateway && make test
	@cargo test --locked -p orbitport-kms-api -p kms-mcp-core -p kms-mcp

mcp-build:
	@cargo build --locked --release -p kms-mcp

mcp-test:
	@cargo test --locked -p orbitport-kms-api -p kms-mcp-core -p kms-mcp

lint:
	@cd plugins && make lint
	@cargo clippy --workspace --all-targets --locked -- -D warnings

fmt:
	@cd plugins && make fmt
	@cargo fmt --all

build: protoc
	@cd plugins && make build
	@cd gateway && make build

e2e:
	@cd gateway && RUST_LOG=info cargo test --test e2e_${E2E_PROFILE} --features localtest

e2e-lazy:
	@cd gateway && RUST_LOG=info cargo test --test e2e_${E2E_PROFILE}

e2e-all:
	@cd gateway && RUST_LOG=info cargo test --test e2e_*

go-e2e:
	@cd plugins && E2E_PROFILE=happy go test ./test -run 'TestBeacon' -timeout 10m -tags e2e -v

go-e2e-offline:
	@cd plugins && E2E_PROFILE=offline go test ./test \
		-run "TestBeacon.*Offline$$" \
		-timeout 10m -tags e2e -v

devenv:
	@OPMOCK_PROFILE=${E2E_PROFILE} docker-compose --env-file=${ENV_FILE} -f dev.docker-compose.yaml up -d

devenv-up: devenv-down docker-build
	@OPMOCK_PROFILE=${E2E_PROFILE} docker-compose --env-file=${ENV_FILE} -f dev.docker-compose.yaml up -d

devenv-down:
	@docker-compose -f dev.docker-compose.yaml down

docker-build:
	@cd plugins && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} docker-build
	@cd gateway && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} docker-build

help:
	@echo ""
	@echo "Usage: make [vars] <cmd>"
	@echo ""
	@echo "Available commands:"
	@echo "  test            Run unit tests"
	@echo "  lint            Run linters"
	@echo "  fmt             Format code"
	@echo "  build           Build the project"
	@echo "  mcp-build       Build the local MCP executable"
	@echo "  mcp-test        Test shared KMS types and local MCP"
	@echo "  e2e             Run end-to-end tests including setup"
	@echo "  e2e-lazy        Run end-to-end tests without setup"
	@echo "  e2e-all         Run all end-to-end tests"
	@echo "  devenv          Start development environment"
	@echo "  devenv-up       Build & start development environment (forced)"
	@echo "  devenv-down     Stop development environment"
	@echo "  docker-build    Build Docker images of the project"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  ENV_FILE        Path to the environment file (default: .dev.env)"
	@echo "  E2E_PROFILE     Profile for end-to-end tests (default: happy)"
	@echo "  DOCKER_TAG      Tag for the Docker image (default: latest)"
	@echo "  CONTAINER_TOOL  Tool for managing containers, e.g. nerdctl (default: docker)"
	@echo ""

default: help
