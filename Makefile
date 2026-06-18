SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

ROOT_DIR := $(CURDIR)
BIN ?= $(ROOT_DIR)/secretr
VELOCITY_BIN ?= $(ROOT_DIR)/velocity
CLI_TEST_SCRIPT ?= $(ROOT_DIR)/scripts/secretr_cli_comprehensive_test.sh

TMP_HOME ?= $(ROOT_DIR)/.tmp_make_home
TMP_GOCACHE ?= $(ROOT_DIR)/.tmp_make_gocache
TMP_SANDBOX_HOME ?= $(ROOT_DIR)/.tmp_make_sandbox_home

VELOCITY_SQL_MILLION_ROWS ?= 1000000
VELOCITY_SQL_MILLION_CHUNK ?= 50000
VELOCITY_DESTRUCTIVE_SOAK_ITERS ?= 800

.PHONY: help build build-secretr build-velocity test test-cli test-cli-commands test-go test-production test-destructive test-soak test-million-sql run-sql-million-example reliability reliability-full reliability-soak reliability-race test-all sandbox-smoke clean

help:
	@echo "Targets:"
	@echo "  make build          - Build secretr and velocity binaries"
	@echo "  make build-secretr  - Build secretr binary"
	@echo "  make build-velocity - Build velocity binary"
	@echo "  make test           - Run comprehensive CLI tests"
	@echo "  make test-cli       - Run comprehensive CLI tests"
	@echo "  make test-cli-commands - Validate CLI command/help surface"
	@echo "  make test-go        - Run Go tests for Secretr packages"
	@echo "  make test-production - Run Velocity production readiness tests"
	@echo "  make test-destructive - Run destructive crash/corruption tests"
	@echo "  make test-soak      - Run longer destructive crash/corruption soak tests"
	@echo "  make test-million-sql - Run the opt-in 1M-row SQL workload"
	@echo "  make run-sql-million-example - Run the 1M-row SQL example"
	@echo "  make reliability    - Run quick DB reliability/DR/negative-condition gate"
	@echo "  make reliability-full - Run full reliability gate including destructive tests"
	@echo "  make reliability-soak - Run full reliability gate plus longer destructive soak"
	@echo "  make reliability-race - Run focused reliability tests under the race detector"
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

test-production:
	go test ./...
	go test -race -run 'TestProductionKV|TestWAL|TestBatchWriter|TestWriter|TestEnvelope' -count=1
	go test -race ./pkg/sqldriver -run 'TestSQLDriver_Production' -count=1

test-destructive:
	go test -tags destructive -run 'TestDestructive|TestProduction' ./...

test-soak:
	VELOCITY_DESTRUCTIVE_SOAK_ITERS=800 go test -tags destructive -run 'TestDestructive|TestProduction' ./...

test-million-sql:
	VELOCITY_SQL_MILLION_ROWS="$(VELOCITY_SQL_MILLION_ROWS)" VELOCITY_SQL_MILLION_CHUNK="$(VELOCITY_SQL_MILLION_CHUNK)" go test -tags million ./pkg/sqldriver -run TestSQLDriver_MillionRowComplexWorkload -count=1 -v

run-sql-million-example:
	cd examples && VELOCITY_SQL_MILLION_ROWS="$(VELOCITY_SQL_MILLION_ROWS)" VELOCITY_SQL_MILLION_CHUNK="$(VELOCITY_SQL_MILLION_CHUNK)" go run ./sql_million_demo

reliability:
	bash ./scripts/reliability_suite.sh quick

reliability-full:
	bash ./scripts/reliability_suite.sh full

reliability-soak:
	VELOCITY_DESTRUCTIVE_SOAK_ITERS="$(VELOCITY_DESTRUCTIVE_SOAK_ITERS)" bash ./scripts/reliability_suite.sh soak

reliability-race:
	bash ./scripts/reliability_suite.sh race

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
