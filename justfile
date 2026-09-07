set shell := ["bash", "-euo", "pipefail", "-c"]

database_url := env_var_or_default("DATABASE_URL", "postgres://gatekeep:gatekeep@localhost:55433/gatekeep")
mysql_database_url := env_var_or_default("MYSQL_DATABASE_URL", "mysql://gatekeep:gatekeep@localhost:53306/gatekeep")
docker_compose := env_var_or_default("DOCKER_COMPOSE", "docker compose")
test_db_up := env_var_or_default("TEST_DB_UP", "1")

fmt:
    cargo fmt --all
    cargo fmt --manifest-path examples/relation-lifecycle/Cargo.toml
    taplo fmt

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo clippy --workspace --lib --bins --all-features -- -D warnings -D clippy::arithmetic_side_effects -D clippy::panic_in_result_fn -D unreachable_pub

supply-chain:
    if ! command -v cargo-deny >/dev/null 2>&1; then echo "cargo-deny is unavailable; run 'mise install'" >&2; exit 2; fi
    cargo deny --all-features check advisories bans licenses sources

test:
    cargo test --workspace --all-features

db-up: db-up-postgres

db-up-postgres:
    {{ docker_compose }} up -d --wait postgres

db-up-mysql:
    {{ docker_compose }} up -d --wait mysql

db-down:
    {{ docker_compose }} down --remove-orphans

test-db: test-db-all

test-db-postgres:
    if [[ "{{ test_db_up }}" == "1" ]]; then just db-up-postgres; fi
    DATABASE_URL="{{ database_url }}" cargo test -p gatekeep-sqlx --test postgres --features postgres-tests -- --ignored --test-threads=1

test-db-mysql:
    if [[ "{{ test_db_up }}" == "1" ]]; then just db-up-mysql; fi
    MYSQL_DATABASE_URL="{{ mysql_database_url }}" cargo test -p gatekeep-sqlx --test mysql --features mysql-tests -- --ignored --test-threads=1

test-db-all: test-db-postgres test-db-mysql

check-relation-consumer:
    scripts/check-relation-consumer.sh

test-relation-consumer:
    scripts/check-relation-consumer.sh --live

check:
    scripts/check-project-gates.sh

clean:
    cargo clean
