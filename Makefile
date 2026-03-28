# AegisOSINT Makefile
# Production-grade OSINT CLI for bug bounty and defensive operations

.PHONY: all setup build lint test coverage e2e run clean install help

# Default target
all: build

# Help
help:
	@echo "AegisOSINT Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  setup     - Install dependencies (runs setup.sh)"
	@echo "  build     - Build release binary"
	@echo "  lint      - Run clippy and format checks"
	@echo "  test      - Run all tests"
	@echo "  coverage  - Run tests with coverage"
	@echo "  e2e       - Run end-to-end tests"
	@echo "  run       - Run the CLI"
	@echo "  install   - Install globally"
	@echo "  clean     - Clean build artifacts"
	@echo "  validate  - Full validation (lint + test + coverage)"
	@echo ""

# Setup dependencies
setup:
	@echo "Setting up AegisOSINT..."
	@chmod +x setup.sh
	@./setup.sh

# Build release binary
build:
	@echo "Building AegisOSINT..."
	cargo build --release
	@echo "Build complete: ./target/release/aegis"

# Build debug binary
build-debug:
	cargo build

# Run linting
lint:
	@echo "Running lints..."
	cargo fmt -- --check
	cargo clippy -- -D warnings
	@echo "Lint passed"

# Format code
fmt:
	cargo fmt

# Run tests
test:
	@echo "Running tests..."
	cargo test --all-features
	@echo "Tests passed"

# Run tests with verbose output
test-verbose:
	cargo test --all-features -- --nocapture

# Run coverage (requires cargo-tarpaulin)
coverage:
	@echo "Running coverage..."
	@command -v cargo-tarpaulin >/dev/null 2>&1 || cargo install cargo-tarpaulin
	cargo tarpaulin --out Html --output-dir coverage --all-features --timeout 300
	@echo "Coverage report: coverage/tarpaulin-report.html"

# Run end-to-end tests
e2e:
	@echo "Running E2E tests..."
	cargo test --test '*' --all-features
	@echo "E2E tests passed"

# Run the CLI
run:
	cargo run --release -- $(ARGS)

# Run in debug mode
run-debug:
	cargo run -- $(ARGS)

# Install globally
install:
	cargo install --path .
	@echo "AegisOSINT installed to ~/.cargo/bin/aegis"

# Full validation
validate: lint test
	@echo "Validation complete"

# Check for security vulnerabilities in dependencies
audit:
	@command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit
	cargo audit

# Generate documentation
docs:
	cargo doc --no-deps --open

# Clean build artifacts
clean:
	cargo clean
	rm -rf coverage/
	@echo "Clean complete"

# Watch for changes and rebuild
watch:
	@command -v cargo-watch >/dev/null 2>&1 || cargo install cargo-watch
	cargo watch -x build

# Check compilation without building
check:
	cargo check --all-features

# Run with example scope
demo:
	@echo "Running demo with example scope..."
	cargo run --release -- scope import --file fixtures/scope.yaml
	cargo run --release -- scope list

# Database migrations (development)
migrate:
	@echo "Running database migrations..."
	cargo run --release -- doctor

# Version information
version:
	@echo "AegisOSINT"
	@cargo pkgid | cut -d'#' -f2
