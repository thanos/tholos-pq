.PHONY: clippy clippy-strict clippy-fix test doctest doc coverage fmt fmt-fix check clean

clippy:
	cargo clippy --all-targets --all-features

clippy-strict:
	cargo clippy --locked --all-targets --all-features -- -D warnings

clippy-fix:
	cargo clippy --fix --allow-dirty --allow-staged

test:
	cargo test --locked --all-targets

doctest:
	cargo test --locked --doc

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps

coverage:
	cargo tarpaulin --tests --out Html --output-dir ./target/coverage

clean:
	cargo clean

fmt:
	cargo fmt --check

fmt-fix:
	cargo fmt

check: fmt clippy-strict test doctest doc
