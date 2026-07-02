SHELL := /usr/bin/env bash

DATABASE_URL ?= postgres://gatekeep:gatekeep@localhost:55433/gatekeep
MYSQL_DATABASE_URL ?= mysql://gatekeep:gatekeep@localhost:53306/gatekeep
DOCKER_COMPOSE ?= docker compose
TEST_DB_UP ?= 1
PNPM_STORE_DIR ?= $(CURDIR)/.pnpm-store
PNPM_XDG_DIR ?= $(CURDIR)/.cache/xdg

.PHONY: fmt clippy test test-db test-db-postgres test-db-mysql test-db-all db-up db-up-postgres db-up-mysql db-down docs docs-install docs-check docs-verify check clean

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-features

db-up: db-up-postgres

db-up-postgres:
	$(DOCKER_COMPOSE) up -d --wait postgres

db-up-mysql:
	$(DOCKER_COMPOSE) up -d --wait mysql

db-down:
	$(DOCKER_COMPOSE) down --remove-orphans

test-db: test-db-postgres

test-db-postgres:
ifeq ($(TEST_DB_UP),1)
	$(MAKE) db-up-postgres
endif
	DATABASE_URL="$(DATABASE_URL)" cargo test -p gatekeep-sqlx --test postgres --features postgres-tests -- --ignored --test-threads=1

test-db-mysql:
ifeq ($(TEST_DB_UP),1)
	$(MAKE) db-up-mysql
endif
	MYSQL_DATABASE_URL="$(MYSQL_DATABASE_URL)" cargo test -p gatekeep-sqlx --test mysql --features mysql-tests -- --ignored --test-threads=1

test-db-all: test-db-postgres test-db-mysql

docs-install:
	XDG_DATA_HOME="$(PNPM_XDG_DIR)/data" XDG_STATE_HOME="$(PNPM_XDG_DIR)/state" NPM_CONFIG_STORE_DIR="$(PNPM_STORE_DIR)" pnpm install --frozen-lockfile

docs-check:
	XDG_DATA_HOME="$(PNPM_XDG_DIR)/data" XDG_STATE_HOME="$(PNPM_XDG_DIR)/state" NPM_CONFIG_STORE_DIR="$(PNPM_STORE_DIR)" pnpm docs:check

docs:
	XDG_DATA_HOME="$(PNPM_XDG_DIR)/data" XDG_STATE_HOME="$(PNPM_XDG_DIR)/state" NPM_CONFIG_STORE_DIR="$(PNPM_STORE_DIR)" pnpm docs:build

docs-verify:
	XDG_DATA_HOME="$(PNPM_XDG_DIR)/data" XDG_STATE_HOME="$(PNPM_XDG_DIR)/state" NPM_CONFIG_STORE_DIR="$(PNPM_STORE_DIR)" pnpm docs:verify

check:
	scripts/check-project-gates.sh

clean:
	cargo clean
	rm -rf docs-site/dist docs-site/.astro
