default:
    @just --list

setup: preflight
    umask 077 && rustup component add rustfmt clippy
    umask 077 && cargo fetch --locked

fast:
    @cargo nextest --version >/dev/null
    bash scripts/ci-local.sh fast

lint:
    bash scripts/ci-local.sh lint

check:
    bash scripts/ci-local.sh required

contract:
    bash scripts/ci-local.sh contract

security:
    bash scripts/ci-local.sh security

docs:
    bash scripts/ci-local.sh docs

family:
    bash scripts/ci-local.sh family

faults:
    bash scripts/ci-local.sh faults

proof-transaction-offline:
    bash ops/ci/proof-transaction-offline.sh

proof-transaction-offline-chaos:
    bash ops/ci/proof-transaction-offline-chaos.sh

proof-synthetic-dogfood:
    bash ops/ci/proof-synthetic-dogfood.sh

verify: check

demo:
    BULLET_DATA_DIR=./target/demo cargo run --locked -p bullet --bin bullet -- demo

audit:
    bash scripts/ci-local.sh audit

egress:
    bash scripts/ci-local.sh egress

nightly:
    bash scripts/ci-local.sh nightly

toolchain-msrv:
    bash scripts/ci-local.sh toolchain-msrv

preflight:
    bash scripts/ci-local.sh preflight

links:
    bash scripts/ci-local.sh links

coverage:
    bash scripts/ci-local.sh coverage

history-secrets:
    bash scripts/ci-local.sh history-secrets

portable-refusal:
    bash scripts/ci-local.sh portable-refusal
