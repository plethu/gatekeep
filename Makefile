SHELL := /usr/bin/env bash

DATABASE_URL ?= postgres://gatekeep:gatekeep@localhost:55433/gatekeep
DOCKER_COMPOSE ?= docker compose

.PHONY: fmt clippy test test-db db-up db-down check clean

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-features

db-up:
	$(DOCKER_COMPOSE) up -d --wait postgres

db-down:
	$(DOCKER_COMPOSE) down --remove-orphans

test-db: db-up
	DATABASE_URL="$(DATABASE_URL)" cargo test -p gatekeep-sqlx --test postgres --features postgres-tests -- --ignored --test-threads=1

check: fmt clippy test

clean:
	cargo clean
