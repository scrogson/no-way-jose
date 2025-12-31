# Default recipe
default: test

# Install dependencies
deps:
    mix deps.get

# Build the project (forces Rust NIF build)
build:
    NOWAYJOSE_BUILD=1 mix compile

# Run tests
test:
    NOWAYJOSE_BUILD=1 mix test

# Run a specific test file or line
test-file file:
    NOWAYJOSE_BUILD=1 mix test {{file}}

# Format all code
fmt:
    mix format
    cd native/nowayjose && cargo fmt

# Check formatting without changing files
fmt-check:
    mix format --check-formatted
    cd native/nowayjose && cargo fmt --check

# Lint all code
lint:
    NOWAYJOSE_BUILD=1 mix compile --warnings-as-errors
    cd native/nowayjose && cargo clippy -- -D warnings

# Audit dependencies for security vulnerabilities
audit:
    cd native/nowayjose && cargo audit

# Run all CI checks
ci: fmt-check lint test

# Build Rust crate directly
cargo-build:
    cd native/nowayjose && cargo build --release

# Check Rust crate
cargo-check:
    cd native/nowayjose && cargo check

# Clean build artifacts
clean:
    mix clean
    cd native/nowayjose && cargo clean

# Generate documentation
docs:
    mix docs

# Create a new release (e.g., `just release v0.4.0`)
release version:
    #!/usr/bin/env bash
    set -euo pipefail

    # Strip 'v' prefix if present for mix.exs
    ver="{{version}}"
    ver="${ver#v}"
    tag="v${ver}"

    # Update version in mix.exs
    sed -i '' "s/@version \".*\"/@version \"${ver}\"/" mix.exs

    # Commit, tag, and push
    git add mix.exs
    git commit -m "Release ${tag}"
    git tag -a "${tag}" -m "Release ${tag}"
    git push origin master --tags