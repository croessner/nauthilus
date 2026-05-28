OUTPUT := nauthilus/bin/nauthilus
CLIENT_OUTPUT := nauthilus/bin/nauthilus-client
OIDCTESTCLIENT_OUTPUT := nauthilus/bin/oidctestclient
SAML2TESTCLIENT_OUTPUT := nauthilus/bin/saml2testclient
ENCRYPTION_SECRET_DECODER_OUTPUT := nauthilus/bin/encryption-secret-decoder
HEALTHCHECK_OUTPUT := nauthilus/bin/nauthilus-healthcheck
GIT_TAG=$(shell git describe --tags --abbrev=0)
GIT_COMMIT=$(shell git rev-parse --short HEAD)
SBOM_OUTPUT_DIR ?= sbom
SBOM_OUTPUT_PREFIX ?= nauthilus
SBOM_DOCKER_IMAGE ?= ghcr.io/croessner/nauthilus:latest
SBOM_DOCKER_PULL ?= true
SBOM_SYFT_VERSION ?= v1.16.0
PROMPT_SOURCE ?= .junie/guidelines.md
PROMPT_TARGET ?= AGENTS.md
GOLANGCI_NEW_FROM_REV ?= HEAD
NAUTHILUS_CONF_DIR ?= /etc/nauthilus
NAUTHILUS_PLUGINS_DIR ?= /usr/local/share/nauthilus/lua-plugins.d
CONFIG_EXPANSION_LDFLAGS := -X github.com/croessner/nauthilus/server/config.nauthilusConfDir=$(NAUTHILUS_CONF_DIR) -X github.com/croessner/nauthilus/server/config.nauthilusPluginsDir=$(NAUTHILUS_PLUGINS_DIR)

export GOEXPERIMENT := runtimesecret

.PHONY: all fix vet test race msan build build-client build-oidctestclient build-saml2testclient build-encryption-secret-decoder build-healthcheck clean install uninstall sbom validate-templates install-hooks sync-prompts sync-prompts-check policy-check generate-vim-syntax generate-vim-syntax-check generate-grpc-proto generate-grpc-auth-proto generate-openapi-bindings generate-openapi-bindings-check generate-openapi-management generate-openapi-management-check identity-proxy-e2e guardrails

all: build build-client build-oidctestclient build-saml2testclient build-encryption-secret-decoder build-healthcheck

fix: ## Run go fix to apply automated code migrations
	go fix ./...

vet: ## Run go vet for static analysis
	go vet ./...

$(OUTPUT) $(CLIENT_OUTPUT) $(OIDCTESTCLIENT_OUTPUT) $(SAML2TESTCLIENT_OUTPUT) $(ENCRYPTION_SECRET_DECODER_OUTPUT) $(HEALTHCHECK_OUTPUT):
	mkdir -p $(dir $@)

test:
	go test -short $$(go list ./... | grep -v /vendor/)

race:
	go test -race -short $$(go list ./... | grep -v /vendor/)

msan:
	go test -msan -short $$(go list ./... | grep -v /vendor/)

build: fix vet $(OUTPUT)
	go build -mod=vendor -trimpath -v -ldflags "-X main.buildTime=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ') -X main.version=$(GIT_TAG)-$(GIT_COMMIT) $(CONFIG_EXPANSION_LDFLAGS)" -o $(OUTPUT) ./server

build-client: $(CLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(CLIENT_OUTPUT) ./client

build-oidctestclient: $(OIDCTESTCLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(OIDCTESTCLIENT_OUTPUT) ./contrib/oidctestclient

build-saml2testclient: $(SAML2TESTCLIENT_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(SAML2TESTCLIENT_OUTPUT) ./contrib/saml2testclient

build-encryption-secret-decoder: $(ENCRYPTION_SECRET_DECODER_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(ENCRYPTION_SECRET_DECODER_OUTPUT) ./contrib/encryption-secret-decoder

build-healthcheck: $(HEALTHCHECK_OUTPUT)
	go build -mod=vendor -trimpath -v -o $(HEALTHCHECK_OUTPUT) ./docker-healthcheck

sbom: ## Generate SBOMs (source and Docker image)
	./scripts/sbom.sh \
		--output-dir $(SBOM_OUTPUT_DIR) \
		--output-prefix $(SBOM_OUTPUT_PREFIX) \
		--source-dir . \
		--docker-image $(SBOM_DOCKER_IMAGE) \
		--docker-pull $(SBOM_DOCKER_PULL) \
		--syft-version $(SBOM_SYFT_VERSION)

clean: ## Remove previous build
	[ -x $(OUTPUT) ] && rm -f $(OUTPUT) || true
	[ -x $(CLIENT_OUTPUT) ] && rm -f $(CLIENT_OUTPUT) || true
	[ -x $(OIDCTESTCLIENT_OUTPUT) ] && rm -f $(OIDCTESTCLIENT_OUTPUT) || true
	[ -x $(SAML2TESTCLIENT_OUTPUT) ] && rm -f $(SAML2TESTCLIENT_OUTPUT) || true
	[ -x $(ENCRYPTION_SECRET_DECODER_OUTPUT) ] && rm -f $(ENCRYPTION_SECRET_DECODER_OUTPUT) || true
	[ -x $(HEALTHCHECK_OUTPUT) ] && rm -f $(HEALTHCHECK_OUTPUT) || true

install: build ## Install nauthilus binary and systemd service
	install -D -m 755 $(OUTPUT) /usr/local/sbin/nauthilus
	install -D -m 644 systemd/nauthilus.service /etc/systemd/system/nauthilus.service
	@echo "Installed nauthilus binary to /usr/local/sbin/nauthilus"
	@echo "Installed systemd service to /etc/systemd/system/nauthilus.service"
	@echo "You may need to run 'systemctl daemon-reload' to use the service"

uninstall: ## Uninstall nauthilus binary and systemd service
	rm -f /usr/local/sbin/nauthilus
	rm -f /etc/systemd/system/nauthilus.service
	@echo "Removed nauthilus binary from /usr/local/sbin/nauthilus"
	@echo "Removed systemd service from /etc/systemd/system/nauthilus.service"
	@echo "You may need to run 'systemctl daemon-reload' to apply changes"

validate-templates: ## Validate Go HTML templates for syntax errors
	go run scripts/validate-templates.go

generate-vim-syntax: ## Generate contrib/vim/syntax/nauthilus.vim from the canonical config dump
	python3 scripts/generate-vim-syntax.py

generate-vim-syntax-check: ## Verify that contrib/vim/syntax/nauthilus.vim is up to date
	python3 scripts/generate-vim-syntax.py --check

generate-grpc-proto: ## Generate committed gRPC API bindings
	./scripts/generate-grpc-proto.sh

generate-grpc-auth-proto: generate-grpc-proto ## Generate committed gRPC API bindings

generate-openapi-bindings: ## Generate committed OpenAPI model and client bindings
	./scripts/generate-openapi-bindings.sh

generate-openapi-bindings-check: ## Verify committed OpenAPI model and client bindings are up to date
	./scripts/generate-openapi-bindings.sh --check

generate-openapi-management: generate-openapi-bindings ## Generate committed OpenAPI management bindings

generate-openapi-management-check: generate-openapi-bindings-check ## Verify committed OpenAPI management bindings are up to date

identity-proxy-e2e: ## Run the split identity-proxy smoke profile
	contrib/identity-proxy-e2e/scripts/run.sh smoke

install-hooks: ## Install Git hooks for development
	./scripts/install-hooks.sh

sync-prompts: ## Sync Junie prompt guidelines into AGENTS.md
	@test -f "$(PROMPT_SOURCE)" || { echo "Source file not found: $(PROMPT_SOURCE)"; exit 1; }
	cp "$(PROMPT_SOURCE)" "$(PROMPT_TARGET)"
	@echo "Synced $(PROMPT_SOURCE) -> $(PROMPT_TARGET)"

sync-prompts-check: ## Verify that AGENTS.md is in sync with .junie/guidelines.md
	@test -f "$(PROMPT_SOURCE)" || { echo "Source file not found: $(PROMPT_SOURCE)"; exit 1; }
	@test -f "$(PROMPT_TARGET)" || { echo "Target file not found: $(PROMPT_TARGET)"; exit 1; }
	@cmp -s "$(PROMPT_SOURCE)" "$(PROMPT_TARGET)" || { echo "$(PROMPT_TARGET) is out of sync with $(PROMPT_SOURCE). Run: make sync-prompts"; exit 1; }
	@echo "Prompt files are in sync"

policy-check: ## Validate mandatory policy documents and text markers
	./scripts/check-policy-docs.sh

guardrails: sync-prompts-check policy-check generate-vim-syntax-check generate-openapi-bindings-check ## Run mandatory local quality gates
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found. Install it and rerun make guardrails"; exit 1; }
	golangci-lint run --new-from-rev=$(GOLANGCI_NEW_FROM_REV) --enable dupl --enable goconst --enable revive --enable govet --enable errcheck --enable gocyclo --enable funlen --enable unused ./...
	go test -short $$(go list ./... | grep -v /vendor/)
