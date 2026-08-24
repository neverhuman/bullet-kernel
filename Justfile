default:
    @just --list

setup:
    rustup component add rustfmt clippy
    cargo fetch

fast:
    bash scripts/ci-local.sh fast

check:
    bash scripts/ci-local.sh required

verify: check

demo:
    BULLET_DATA_DIR=./target/demo cargo run -p bullet -- demo
