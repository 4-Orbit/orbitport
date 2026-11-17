ENV_FILE?=".dev.env"
E2E_PROFILE?=happy
CONTAINER_TOOL?=docker ## CONTAINER_TOOL=nerdctl
DOCKER_TAG?=latest ## DOCKER_TAG=v*.*.*
# docker-compose v1 when installed, otherwise the v2 plugin.
COMPOSE?=$(shell command -v docker-compose >/dev/null 2>&1 && echo docker-compose || echo docker compose)
# Optional runtime base overrides for docker-build (default: dhi.io images).
PLUGIN_RUNTIME_IMAGE?=
GATEWAY_RUNTIME_IMAGE?=

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
	@OPMOCK_PROFILE=${E2E_PROFILE} ${COMPOSE} --env-file=${ENV_FILE} -f dev.docker-compose.yaml up -d

devenv-up: devenv-down docker-build
	@OPMOCK_PROFILE=${E2E_PROFILE} ${COMPOSE} --env-file=${ENV_FILE} -f dev.docker-compose.yaml up -d

devenv-down:
	@${COMPOSE} -f dev.docker-compose.yaml down

docker-build:
	@cd plugins && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} RUNTIME_IMAGE=${PLUGIN_RUNTIME_IMAGE} docker-build
	@cd gateway && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} RUNTIME_IMAGE=${GATEWAY_RUNTIME_IMAGE} docker-build

## ---------------------------------------------------------------------------
## 4Orbit: per-agent Cedar policy, policy plugin, console (see DEPLOY.md)
## ---------------------------------------------------------------------------
# Public distroless runtimes, so the stack builds without a dhi.io login. To
# use the hardened images instead (needs `docker login dhi.io`):
#   make FOURORBIT_PLUGIN_RUNTIME=dhi.io/static:20250419-debian13 \
#        FOURORBIT_GATEWAY_RUNTIME=dhi.io/static:20250419-glibc 4orbit-build
FOURORBIT_PLUGIN_RUNTIME?=gcr.io/distroless/static-debian13:nonroot
FOURORBIT_GATEWAY_RUNTIME?=gcr.io/distroless/cc-debian13:nonroot
FOURORBIT_ENV_FILE?=.4orbit.env
FOURORBIT_COMPOSE=FOURORBIT_UID=$$(id -u) FOURORBIT_GID=$$(id -g) OPMOCK_PROFILE=${E2E_PROFILE} \
	${COMPOSE} --env-file .dev.env $(if $(wildcard ${FOURORBIT_ENV_FILE}),--env-file ${FOURORBIT_ENV_FILE}) \
	-f dev.docker-compose.yaml -f local-pat.compose.yaml -f 4orbit.compose.yaml

4orbit-build:
	@cd plugins && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} RUNTIME_IMAGE=${FOURORBIT_PLUGIN_RUNTIME} docker-build mocker-docker-build
	@cd plugins && ${CONTAINER_TOOL} build --build-arg RUNTIME_IMAGE=${FOURORBIT_PLUGIN_RUNTIME} --build-arg BUILD_TARGET=fourorbit-seed -t op-fourorbit-seed:${DOCKER_TAG} .
	@cd gateway && make CONTAINER_TOOL=${CONTAINER_TOOL} DOCKER_TAG=${DOCKER_TAG} RUNTIME_IMAGE=${FOURORBIT_GATEWAY_RUNTIME} docker-build
	@${CONTAINER_TOOL} build -t op-console:${DOCKER_TAG} console

4orbit-up: 4orbit-build 4orbit

4orbit:
	@mkdir -p .4orbit/tokens && chmod 700 .4orbit .4orbit/tokens
	@${FOURORBIT_COMPOSE} up -d --no-build

4orbit-seed:
	@mkdir -p .4orbit/tokens && chmod 700 .4orbit .4orbit/tokens
	@${FOURORBIT_COMPOSE} run --rm --no-deps fourorbit-seed

4orbit-ps:
	@${FOURORBIT_COMPOSE} ps -a

4orbit-logs:
	@${FOURORBIT_COMPOSE} logs --tail 100 -f gateway plugin-kms plugin-policy console

4orbit-stop:
	@${FOURORBIT_COMPOSE} stop

4orbit-down:
	@${FOURORBIT_COMPOSE} down

4orbit-test:
	@cd plugins && go test ./pkg/core/authz/... ./pkg/plugin/policy/... ./pkg/plugin/kms/... ./pkg/plugin/auth/... ./pkg/plugin/authnoop/... ./pkg/plugin/patissuer/...
	@cargo test --locked -p gateway --lib --test agent_identity --test agent_delegation_route --test account_filter
	@cd console && npm test

4orbit-e2e:
	@./scripts/4orbit/e2e.sh

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
	@echo "  4orbit-up       Build images (public runtimes) and start the 4Orbit stack"
	@echo "  4orbit          Start the 4Orbit stack from existing images"
	@echo "  4orbit-seed     Mint tokens, create demo keys, load + activate policy v1"
	@echo "  4orbit-ps       Show 4Orbit stack containers"
	@echo "  4orbit-logs     Follow gateway, KMS, policy and console logs"
	@echo "  4orbit-stop     Stop the 4Orbit stack (keeps containers)"
	@echo "  4orbit-down     Remove the 4Orbit stack (loses in-memory OpenBao data)"
	@echo "  4orbit-test     4Orbit unit tests (Go, Rust, console)"
	@echo "  4orbit-e2e      End-to-end checks against the running 4Orbit stack"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  ENV_FILE        Path to the environment file (default: .dev.env)"
	@echo "  E2E_PROFILE     Profile for end-to-end tests (default: happy)"
	@echo "  DOCKER_TAG      Tag for the Docker image (default: latest)"
	@echo "  CONTAINER_TOOL  Tool for managing containers, e.g. nerdctl (default: docker)"
	@echo ""

default: help
