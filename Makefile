SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

ROOT_DIR := $(CURDIR)
BIN ?= $(ROOT_DIR)/secretr
VELOCITY_BIN ?= $(ROOT_DIR)/velocity
CLI_TEST_SCRIPT ?= $(ROOT_DIR)/scripts/secretr_cli_comprehensive_test.sh

TMP_HOME ?= $(ROOT_DIR)/.tmp_make_home
TMP_GOCACHE ?= $(ROOT_DIR)/.tmp_make_gocache
TMP_SANDBOX_HOME ?= $(ROOT_DIR)/.tmp_make_sandbox_home

.PHONY: help build build-secretr build-velocity test test-cli test-cli-commands test-go test-all sandbox-smoke clean

help:
	@echo "Targets:"
	@echo "  make build          - Build secretr and velocity binaries"
	@echo "  make build-secretr  - Build secretr binary"
	@echo "  make build-velocity - Build velocity binary"
	@echo "  make test           - Run comprehensive CLI tests"
	@echo "  make test-cli       - Run comprehensive CLI tests"
	@echo "  make test-cli-commands - Validate CLI command/help surface"
	@echo "  make test-go        - Run Go tests for Secretr packages"
	@echo "  make test-all       - Run CLI and Go tests"
	@echo "  make sandbox-smoke  - Run sandbox exec smoke checks"
	@echo "  make clean          - Remove temporary test/build artifacts"

build: build-secretr build-velocity

build-secretr:
	@mkdir -p "$(TMP_HOME)" "$(TMP_GOCACHE)"
	HOME="$(TMP_HOME)" GOCACHE="$(TMP_GOCACHE)" go build -o "$(BIN)" ./cmd/secretr

build-velocity:
	@mkdir -p "$(TMP_HOME)" "$(TMP_GOCACHE)"
	HOME="$(TMP_HOME)" GOCACHE="$(TMP_GOCACHE)" go build -o "$(VELOCITY_BIN)" ./cmd/velocity

test: test-cli

test-cli:
	chmod +x "$(CLI_TEST_SCRIPT)"
	HOME="$(ROOT_DIR)/.tmp_home_cli_test_runner" BIN="$(BIN)" "$(CLI_TEST_SCRIPT)"

test-cli-commands:
	@mkdir -p "$(ROOT_DIR)/.tmp_home_cli_cmds"
	@echo "[cli-commands] checking root help"
	@HOME="$(ROOT_DIR)/.tmp_home_cli_cmds" "$(BIN)" --help >/dev/null
	@echo "[cli-commands] checking top-level command help"
	@set -e; \
	commands="$$( HOME="$(ROOT_DIR)/.tmp_home_cli_cmds" "$(BIN)" --help 2>/dev/null | awk '/^COMMANDS:/{flag=1; next} /^GLOBAL OPTIONS:/{flag=0} flag{print $$1}' | sed 's/,//' | grep -vE '^(help|h)$$' | grep -vE ':$$' )"; \
	for c in $$commands; do \
	  echo "  - $$c --help"; \
	  HOME="$(ROOT_DIR)/.tmp_home_cli_cmds" "$(BIN)" "$$c" --help >/dev/null; \
	done
	@echo "[cli-commands] checking key subcommands"
	@set -e; \
	for c in auth secret object folder data key backup identity session access role policy audit share org incident envelope admin ssh cicd exec monitoring alert compliance pipeline; do \
	  if HOME="$(ROOT_DIR)/.tmp_home_cli_cmds" "$(BIN)" "$$c" --help >/dev/null 2>&1; then \
	    subs="$$( HOME="$(ROOT_DIR)/.tmp_home_cli_cmds" "$(BIN)" "$$c" --help 2>/dev/null | awk '/^COMMANDS:/{flag=1; next} /^OPTIONS:/{flag=0} flag{print $$1}' | sed 's/,//' )"; \
	    for s in $$subs; do \
	      [ -z "$$s" ] && continue; \
	      echo "  - $$c $$s --help"; \
	      HOME="$(ROOT_DIR)/.tmp_home_cli_cmds" "$(BIN)" "$$c" "$$s" --help >/dev/null || true; \
	    done; \
	  fi; \
	done
	@echo "[cli-commands] done"

test-go:
	@mkdir -p "$(TMP_HOME)" "$(TMP_GOCACHE)"
	HOME="$(TMP_HOME)" GOCACHE="$(TMP_GOCACHE)" go test ./internal/secretr/...
	HOME="$(TMP_HOME)" GOCACHE="$(TMP_GOCACHE)" go test ./cmd/secretr ./cmd/velocity

test-all: test-cli-commands test-cli test-go

sandbox-smoke:
	@mkdir -p "$(TMP_SANDBOX_HOME)"
	rm -rf "$(TMP_SANDBOX_HOME)"
	mkdir -p "$(TMP_SANDBOX_HOME)"
	HOME="$(TMP_SANDBOX_HOME)" SECRETR_ALLOW_INSECURE_PASSWORD_ENV=true SECRETR_PASSWORD='StrongPass123!' SECRETR_PASSWORD_CONFIRM='StrongPass123!' "$(BIN)" auth init --name "Admin User" --email "admin@example.com"
	HOME="$(TMP_SANDBOX_HOME)" SECRETR_ALLOW_INSECURE_PASSWORD_ENV=true SECRETR_PASSWORD='StrongPass123!' "$(BIN)" auth login --email "admin@example.com"
	HOME="$(TMP_SANDBOX_HOME)" "$(BIN)" exec --command /bin/echo --isolation auto hello
	HOME="$(TMP_SANDBOX_HOME)" "$(BIN)" exec --command /bin/echo --isolation host hello

clean:
	rm -rf "$(TMP_HOME)" "$(TMP_GOCACHE)" "$(TMP_SANDBOX_HOME)" \
		"$(ROOT_DIR)/.tmp_home_cli_test_runner" "$(ROOT_DIR)/.tmp_secretr_cli_home" \
		"$(ROOT_DIR)/.tmp_secretr_cli_work" "$(ROOT_DIR)/.tmp_secretr_cli_logs" \
		"$(ROOT_DIR)/.tmp_secretr_cli_gocache"
