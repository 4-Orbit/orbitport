GOPACKAGES=$(shell go list ./...)
DOCKER_IMAGE?=op-plugin
DOCKER_TAG?=latest
DOCKER_CONTAINER_NAME?=plugin
GOLOG_LOG_LEVEL?=debug
ENV_FILE?=.env
MOCKER_DOCKER_IMAGE?=op-mocker
CONTAINER_TOOL?=docker ## CONTAINER_TOOL=nerdctl 

deps:
	@go mod download

protoc-deps:
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

protoc: protoc-deps
	@cd ../ && ./plugins/scripts/protoc.sh

protoc-dry-run: protoc-deps
	@cd ../ && ./plugins/scripts/protoc.sh --dry-run

test: deps
	@GOLOG_LOG_LEVEL=${GOLOG_LOG_LEVEL} go test -v $(GOPACKAGES)

race: deps
	@go test -race $(GOPACKAGES)

coverage: deps
	@go test -cover -coverprofile cover.out $(GOPACKAGES)
# 	@go tool cover -html=cover.out

fmt: deps
	@go fmt ./...

tidy: deps
	@go mod tidy

lint: deps
	@golangci-lint run ./...

build: deps
	@go build -o bin/ ./cmd/...

run: build
	@GOLOG_LOG_LEVEL=${GOLOG_LOG_LEVEL} ./bin/plugin -e ${ENV_FILE}

docker-build:
	@${CONTAINER_TOOL} build $(if ${RUNTIME_IMAGE},--build-arg RUNTIME_IMAGE=${RUNTIME_IMAGE}) -t ${DOCKER_IMAGE}:${DOCKER_TAG} .

docker-clean:
	@${CONTAINER_TOOL} rm -f ${DOCKER_CONTAINER_NAME} 2> /dev/null

docker-run: docker-clean docker-build
	@${CONTAINER_TOOL} run -p 8080:8080 -e GOLOG_LOG_LEVEL=${GOLOG_LOG_LEVEL} -v ./${ENV_FILE}:/.env \
		--name ${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE}:${DOCKER_TAG}

mocker-docker-build:
	@${CONTAINER_TOOL} build $(if ${RUNTIME_IMAGE},--build-arg RUNTIME_IMAGE=${RUNTIME_IMAGE}) -t ${MOCKER_DOCKER_IMAGE}:${DOCKER_TAG} --build-arg BUILD_TARGET=mocker .

help:
	@echo ""
	@echo "Usage: make <cmd>"
	@echo ""
	@echo "Available commands:"
	@echo "- deps: install dependencies"
	@echo "- protoc: generate protobuf files"
	@echo "- protoc-dry-run: dry run for protoc to see affected files"
	@echo "- test: run tests"
	@echo "- race: run tests with race condition detection"
	@echo "- coverage: run tests and generate a coverage report"
	@echo "- fmt: format the code"
	@echo "- tidy: clean up go.mod and go.sum"
	@echo "- lint: run linting on the codebase"
	@echo "- build: build the project binary"
	@echo "- run: build and run the project locally"
	@echo "- docker-build: build the Docker image"
	@echo "- docker-clean: remove the Docker container if it exists"
	@echo "- docker-run: build and run the project in a Docker container"
	@echo ""

default: help