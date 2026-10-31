GO ?= go
GO_MODULES := $(patsubst %/go.mod,%,$(wildcard */go.mod))

## test: run tests in every Go example
## lint: check every Go example with its configured golangci-lint
## fmt: format every Go example with its configured golangci-lint
## install-tools: download tool dependencies for every Go example
test lint fmt install-tools:
	@set -e; for module in $(GO_MODULES); do \
		$(MAKE) -C "$$module" $@ GO="$(GO)"; \
	done

.PHONY: test lint fmt install-tools
