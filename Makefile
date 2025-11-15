.PHONY: clippy clippy-fix test coverage clean

# Run clippy lints (warnings only, not errors)
clippy:
	cargo clippy --all-targets --all-features

# Run clippy with warnings treated as errors (for CI)
clippy-strict:
	cargo clippy --all-targets --all-features -- -D warnings

# Run clippy and automatically fix issues where possible
clippy-fix:
	cargo clippy --fix --allow-dirty --allow-staged

# Run all tests
test:
	cargo test --all-targets

# Run tests with coverage
coverage:
	cargo tarpaulin --tests --exclude-files 'src/main.rs' --out Html --output-dir ./target/coverage

# Clean build artifacts
clean:
	cargo clean

# Run clippy on tests as well (with warnings allowed since tests use unwrap)
clippy-tests:
	cargo clippy --all-targets --all-features

# Check code formatting
fmt:
	cargo fmt --check

# Format code
fmt-fix:
	cargo fmt

# Full check: format, clippy, and tests
check: fmt clippy test

