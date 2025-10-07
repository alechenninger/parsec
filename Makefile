.PHONY: help proto clean test build

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

proto: ## Generate code from proto files
	@echo "Generating proto files..."
	buf generate

clean: ## Clean generated files
	@echo "Cleaning..."
	rm -rf api/gen

test: ## Run tests
	go test -v -race ./...

build: ## Build the parsec binary
	go build -o bin/parsec ./cmd/parsec

run: build ## Run parsec locally
	./bin/parsec

.DEFAULT_GOAL := help

