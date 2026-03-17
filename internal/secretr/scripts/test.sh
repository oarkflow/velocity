#!/bin/bash
# Secretr Platform - Comprehensive Test Script
# Tests all core modules and CLI functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Test directory
TEST_DIR="/tmp/secretr-test-$$"
SECRETR_BIN="./secretr"

# Setup
setup() {
    echo -e "${BLUE}=== Setting up test environment ===${NC}"
    mkdir -p "$TEST_DIR"
    export SECRETR_HOME="$TEST_DIR/.secretr"
    mkdir -p "$SECRETR_HOME"

    # Build if needed
    if [ ! -f "$SECRETR_BIN" ]; then
        echo "Building secretr..."
        go build -o secretr ./cmd/secretr
    fi

    echo -e "${GREEN}✓ Test environment ready at $TEST_DIR${NC}"
}

# Cleanup
cleanup() {
    echo -e "${BLUE}=== Cleaning up ===${NC}"
    rm -rf "$TEST_DIR"
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Test helper functions
test_pass() {
    echo -e "${GREEN}✓ PASS: $1${NC}"
    ((TESTS_PASSED++))
}

test_fail() {
    echo -e "${RED}✗ FAIL: $1${NC}"
    if [ -n "$2" ]; then
        echo -e "${RED}  Error: $2${NC}"
    fi
    ((TESTS_FAILED++))
}

test_skip() {
    echo -e "${YELLOW}○ SKIP: $1${NC}"
    ((TESTS_SKIPPED++))
}

section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# =============================================================================
# CLI Tests
# =============================================================================

test_cli_help() {
    section "CLI Help Tests"

    # Test main help
    if $SECRETR_BIN --help &>/dev/null; then
        test_pass "Main help displays correctly"
    else
        test_fail "Main help failed"
    fi

    # Test version
    if $SECRETR_BIN --version &>/dev/null; then
        test_pass "Version displays correctly"
    else
        test_fail "Version display failed"
    fi

    # Test each command group help
    for cmd in auth identity device session key secret file access role policy audit share backup org incident admin; do
        if $SECRETR_BIN $cmd --help &>/dev/null; then
            test_pass "Help for '$cmd' command"
        else
            test_fail "Help for '$cmd' command"
        fi
    done
}

test_cli_subcommands() {
    section "CLI Subcommand Tests"

    # Test secret subcommands
    for subcmd in create get list update delete history rotate export; do
        if $SECRETR_BIN secret $subcmd --help &>/dev/null; then
            test_pass "secret $subcmd --help"
        else
            test_fail "secret $subcmd --help"
        fi
    done

    # Test key subcommands
    for subcmd in generate list rotate destroy export import split; do
        if $SECRETR_BIN key $subcmd --help &>/dev/null; then
            test_pass "key $subcmd --help"
        else
            test_fail "key $subcmd --help"
        fi
    done

    # Test file subcommands
    for subcmd in upload download list delete seal unseal shred; do
        if $SECRETR_BIN file $subcmd --help &>/dev/null; then
            test_pass "file $subcmd --help"
        else
            test_fail "file $subcmd --help"
        fi
    done
}

# =============================================================================
# Unit Tests
# =============================================================================

test_go_unit_tests() {
    section "Go Unit Tests"

    # Run all tests with race detection
    if go test -v -race ./... 2>&1 | tee "$TEST_DIR/test-output.log"; then
        test_pass "All Go unit tests passed"
    else
        test_fail "Some Go unit tests failed" "See $TEST_DIR/test-output.log"
    fi
}

test_crypto_module() {
    section "Crypto Module Tests"

    go test -v -run "TestCrypto" ./internal/core/crypto/... 2>&1 && \
        test_pass "Crypto engine tests" || \
        test_fail "Crypto engine tests"

    go test -v -run "TestEncrypt" ./internal/core/crypto/... 2>&1 && \
        test_pass "Encryption tests" || \
        test_fail "Encryption tests"

    go test -v -run "TestSign" ./internal/core/crypto/... 2>&1 && \
        test_pass "Signing tests" || \
        test_fail "Signing tests"
}

test_storage_module() {
    section "Storage Module Tests"

    go test -v -run "TestStore" ./internal/storage/... 2>&1 && \
        test_pass "Storage tests" || \
        test_fail "Storage tests"

    go test -v -run "TestAudit" ./internal/storage/... 2>&1 && \
        test_pass "Audit storage tests" || \
        test_fail "Audit storage tests"
}

test_identity_module() {
    section "Identity Module Tests"

    go test -v ./internal/core/identity/... 2>&1 && \
        test_pass "Identity manager tests" || \
        test_fail "Identity manager tests"
}

test_secrets_module() {
    section "Secrets Module Tests"

    go test -v ./internal/core/secrets/... 2>&1 && \
        test_pass "Secrets vault tests" || \
        test_fail "Secrets vault tests"
}

test_keys_module() {
    section "Keys Module Tests"

    go test -v ./internal/core/keys/... 2>&1 && \
        test_pass "Key manager tests" || \
        test_fail "Key manager tests"
}

test_files_module() {
    section "Files Module Tests"

    go test -v ./internal/core/files/... 2>&1 && \
        test_pass "File vault tests" || \
        test_fail "File vault tests"
}

test_access_module() {
    section "Access Control Module Tests"

    go test -v ./internal/core/access/... 2>&1 && \
        test_pass "Access control tests" || \
        test_fail "Access control tests"
}

test_policy_module() {
    section "Policy Module Tests"

    go test -v ./internal/core/policy/... 2>&1 && \
        test_pass "Policy engine tests" || \
        test_fail "Policy engine tests"
}

test_audit_module() {
    section "Audit Module Tests"

    go test -v ./internal/core/audit/... 2>&1 && \
        test_pass "Audit engine tests" || \
        test_fail "Audit engine tests"
}

# =============================================================================
# Integration Tests
# =============================================================================

test_integration() {
    section "Integration Tests"

    # Test complete workflow (requires proper setup)
    test_skip "Full workflow integration test (requires authenticated session)"
}

# =============================================================================
# Security Tests
# =============================================================================

test_security() {
    section "Security Tests"

    # Test secure memory
    go test -v -run "TestSecure" ./internal/security/... 2>&1 && \
        test_pass "Secure memory tests" || \
        test_fail "Secure memory tests"

    # Check for common vulnerabilities
    echo "Running gosec security scanner..."
    if command -v gosec &>/dev/null; then
        if gosec -quiet ./... 2>&1; then
            test_pass "Security scan (gosec)"
        else
            test_fail "Security scan found issues"
        fi
    else
        test_skip "Security scan (gosec not installed)"
    fi
}

# =============================================================================
# Benchmark Tests
# =============================================================================

test_benchmarks() {
    section "Benchmark Tests"

    echo "Running crypto benchmarks..."
    go test -bench=. -benchmem ./internal/core/crypto/... 2>&1 | tee "$TEST_DIR/crypto-bench.log" && \
        test_pass "Crypto benchmarks" || \
        test_fail "Crypto benchmarks"

    echo "Benchmark results saved to $TEST_DIR/crypto-bench.log"
}

# =============================================================================
# Permission Gate Tests
# =============================================================================

test_permission_gates() {
    section "Permission Gate Tests"

    go test -v ./internal/cli/middleware/... 2>&1 && \
        test_pass "Permission middleware tests" || \
        test_fail "Permission middleware tests"
}

# =============================================================================
# Exit Code Tests
# =============================================================================

test_exit_codes() {
    section "Exit Code Tests"

    # Test that unauthenticated commands return proper exit codes
    # Note: These expect specific exit codes, adjust based on implementation

    # Help should exit 0
    $SECRETR_BIN --help >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        test_pass "Exit code 0 for --help"
    else
        test_fail "Exit code 0 for --help"
    fi

    # Invalid command should exit non-zero
    $SECRETR_BIN invalid-command >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        test_pass "Non-zero exit code for invalid command"
    else
        test_fail "Non-zero exit code for invalid command"
    fi
}

# =============================================================================
# Main Test Runner
# =============================================================================

run_all_tests() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     SECRETR PLATFORM - COMPREHENSIVE TEST SUITE              ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    setup

    # CLI Tests
    test_cli_help
    test_cli_subcommands
    test_exit_codes

    # Unit Tests
    test_go_unit_tests

    # Module Tests
    test_crypto_module
    test_storage_module
    test_identity_module
    test_secrets_module
    test_keys_module
    test_files_module
    test_access_module
    test_policy_module
    test_audit_module

    # Security Tests
    test_security
    test_permission_gates

    # Integration Tests
    test_integration

    # Benchmarks (optional)
    if [ "$RUN_BENCHMARKS" = "1" ]; then
        test_benchmarks
    fi

    cleanup

    # Summary
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                        TEST SUMMARY                           ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Passed:  $TESTS_PASSED${NC}"
    echo -e "${RED}  Failed:  $TESTS_FAILED${NC}"
    echo -e "${YELLOW}  Skipped: $TESTS_SKIPPED${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Parse arguments
case "${1:-all}" in
    all)
        run_all_tests
        ;;
    cli)
        setup
        test_cli_help
        test_cli_subcommands
        cleanup
        ;;
    unit)
        setup
        test_go_unit_tests
        cleanup
        ;;
    crypto)
        test_crypto_module
        ;;
    storage)
        test_storage_module
        ;;
    security)
        test_security
        ;;
    bench)
        RUN_BENCHMARKS=1
        test_benchmarks
        ;;
    help)
        echo "Usage: $0 [all|cli|unit|crypto|storage|security|bench|help]"
        echo ""
        echo "Options:"
        echo "  all      - Run all tests (default)"
        echo "  cli      - Run CLI tests only"
        echo "  unit     - Run Go unit tests only"
        echo "  crypto   - Run crypto module tests"
        echo "  storage  - Run storage module tests"
        echo "  security - Run security tests"
        echo "  bench    - Run benchmarks"
        echo "  help     - Show this help"
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use '$0 help' for usage"
        exit 1
        ;;
esac
