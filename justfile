set shell := ["bash", "-euo", "pipefail", "-c"]

database_url := env_var_or_default("DATABASE_URL", "postgres://gatekeep:gatekeep@localhost:55433/gatekeep")
mysql_database_url := env_var_or_default("MYSQL_DATABASE_URL", "mysql://gatekeep:gatekeep@localhost:53306/gatekeep")
docker_compose := env_var_or_default("DOCKER_COMPOSE", "docker compose")
test_db_up := env_var_or_default("TEST_DB_UP", "1")

fmt:
    cargo fmt --all

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

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

check:
    scripts/check-project-gates.sh

clean:
    cargo clean
