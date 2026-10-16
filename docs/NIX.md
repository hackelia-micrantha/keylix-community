# Nix development and CI environment

Keylix owns a repository-local Nix flake for reproducible development and canonical CI tooling.

The flake is intentionally a **toolchain/environment boundary**, not an authorization mechanism and not a replacement for Cargo package metadata or release semantics.

## Supported systems

The flake declares development shells for:

- `x86_64-linux`
- `aarch64-linux`
- `x86_64-darwin`
- `aarch64-darwin`

## Stable development shell

Enter the default shell with:

```sh
nix develop
```

The stable Rust toolchain is derived from the repository-owned `rust-toolchain.toml`, currently Rust 1.88.0 with `rustfmt` and Clippy.

The shell also provides the native tooling used by existing deterministic tests and build scripts, including Python, Git, curl, CMake, Ninja, Perl, and `pkg-config`.

The normal canonical quality commands remain Cargo commands inside that shell:

```sh
cargo fetch --locked
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --no-deps
```

Dependency/advisory policy remains owned by `deny.toml` and the checksum-pinned cargo-deny bootstrap script.

## Fuzz shell

Enter the nightly shell with:

```sh
nix develop .#fuzz
```

The nightly compiler is selected from the locked `rust-overlay` input. The repository continues to install the reviewed, checksum-pinned cargo-fuzz release through `.github/scripts/install-cargo-fuzz.sh`; the flake does not silently substitute a different cargo-fuzz version.

Inside the fuzz shell, use the Nix-provided nightly toolchain directly:

```sh
cargo check --manifest-path fuzz/Cargo.toml --bins
cargo fuzz list --manifest-path fuzz/Cargo.toml
```

The `cargo +nightly` spelling is deliberately unnecessary because that `+toolchain` dispatch is a rustup proxy convention.

## Flake checks and formatting

Run the deterministic flake checks with:

```sh
nix flake check
```

The initial check validates that the declared stable Rust/Python toolchain is realizable and exposes the expected Rust 1.88.0, Cargo, Clippy, rustfmt, and Python commands.

Format Nix files with:

```sh
nix fmt
```

## CI boundary

Private canonical GitHub Actions run on the repository-scoped Dubnium selector and enter these development shells with `nix develop`. This means the runner image needs Nix, but does not need to bootstrap Rust with `rustup-init` or weaken an executable-temp-directory policy.

Public `keylix-community` pull-request CI remains an untrusted-contribution-safe GitHub-hosted boundary. Publication of this flake to the public repository must use the normal reviewed projection path.

## Public release and downstream consumption

The Micrantha release/integration contract distinguishes the **canonical development flake** from the **public release-consumption surface**.

```text
private keylix flake
  -> canonical development / CI / publication validation

reviewed projection
  -> keylix-community flake
       -> public release tag/revision
            -> supported downstream consumers
```

The canonical flake is not a supported private-source dependency for Dubnium, dotfiles, or other consumers. A supported integration must pin the public `hackelia-micrantha/keylix-community` release tag/revision or an immutable artifact published by that release.

Before the first public release is declared complete, the reviewed projection must place `flake.nix` and `flake.lock` in `keylix-community`; publication provenance then binds that public flake to the exact canonical source revision.

Downstream Nix integration must remain credential-free. When a public release flake fetches an immutable archive or binary asset, it must use a real integrity/SRI hash rather than a fake hash or mutable branch reference. Dependency bumps are explicit reviewed changes and should verify the installed version/contract in downstream CI.

## Current package/app scope

Keylix is currently a Rust library workspace and does not expose a canonical executable. The flake therefore does **not** invent an `apps.default` wrapper or pretend a library workspace is a command-line program.

Cargo remains authoritative for the six publishable crates and their exact coordinated release graph. The public community release is the release identity; Cargo packages are produced from that exact committed public release revision.

Nix package/app outputs are added only when Keylix owns a genuine installable program or a deliberately designed library package derivation. When Keylix ships a real verifier/server or CLI, the public release flake must expose the real package/app and its checks must validate the complete install surface, including:

- executable `--help` and `--version` smoke checks;
- required section-1 man pages under `share/man/man1`;
- required public schemas/examples/fixtures installed with the package where they are part of the contract;
- offline, deterministic, credential-free package validation.

A future binary-oriented public flake may fetch immutable reviewed release assets instead of rebuilding implementation source when that is appropriate. It must still preserve the public protocol/security/conformance semantics required by Keylix's publication boundary.

This keeps the flake independent of Dubnium implementation paths, credentials, services, and private deployment configuration while giving downstream consumers a stable public integration surface.

The public release and downstream integration contract is documented above.
