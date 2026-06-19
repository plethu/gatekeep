SHELL := /usr/bin/env bash

.PHONY: fmt clippy test check clean

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-features

check: fmt clippy test

clean:
	cargo clean
