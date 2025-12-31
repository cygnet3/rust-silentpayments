# Once just v1.39.0 is widely deployed, simplify with the `read` function.
NIGHTLY_VERSION := trim(shell('cat "$1"', justfile_directory() / "nightly-version"))

_default:
  @just --list

# Install rbmt (Rust Bitcoin Maintainer Tools).
@_install-rbmt:
  cargo install --quiet --git https://github.com/rust-bitcoin/rust-bitcoin-maintainer-tools.git --rev $(cat {{justfile_directory()}}/rbmt-version) cargo-rbmt

# Cargo check everything.
check:
  cargo check --all --all-targets --all-features

# Cargo build everything.
build:
  cargo build --all --all-targets --all-features

# Test everything.
test:
  cargo test --all-targets --all-features

# Lint everything.
lint:
  cargo +{{NIGHTLY_VERSION}} clippy --all-targets --all-features -- --deny warnings

# Run cargo fmt
fmt:
  cargo +{{NIGHTLY_VERSION}} fmt --all

# Generate documentation.
docsrs *flags:
  RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +{{NIGHTLY_VERSION}} doc --all-features {{flags}}

# Update the recent and minimal lock files using rbmt.
[group('tools')]
@update-lock-files: _install-rbmt
  rustup run {{NIGHTLY_VERSION}} cargo rbmt lock

# Run CI tasks with rbmt.
[group('ci')]
@ci task toolchain="stable" lock="recent": _install-rbmt
  RBMT_LOG_LEVEL=quiet rustup run {{toolchain}} cargo rbmt --lock-file {{lock}} {{task}}

# Test crate.
[group('ci')]
ci-test: (ci "test stable")

# Lint crate.
[group('ci')]
ci-lint: (ci "lint" NIGHTLY_VERSION)

# Bitcoin core integration tests.
[group('ci')]
ci-integration: (ci "integration")
