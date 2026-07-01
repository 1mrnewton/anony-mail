# Contributing

Thanks for your interest in improving tempmail-backend! Contributions of all
kinds are welcome: bug reports, feature ideas, docs, and code.

## Development setup

You need a recent Rust toolchain (edition 2024, i.e. Rust >= 1.85).

```bash
# Build
cargo build

# Run the test suite (no database required — tests use the in-memory store)
cargo test
```

To run the service locally you also need PostgreSQL. See the
[README](README.md) for configuration and `docker compose up` for a one-command
dev environment.

## Before opening a pull request

Please make sure the following all pass, since CI enforces them:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- Keep changes focused; one logical change per PR.
- Add or update tests for behavior changes.
- Update the README / `.env.example` when you add or change configuration.
- Write clear commit messages (a `type: summary` prefix such as `feat:`,
  `fix:`, `docs:`, `refactor:`, `test:`, `chore:` is appreciated).

## Scope

This is an **inbound-only** mail receiver. Outbound sending, SPF/DKIM/DMARC
verification, and blocklist checks are intentionally out of scope for now (see
the README's "Out of scope" notes). Proposals that add these are welcome for
discussion first via an issue.

## License

By contributing, you agree that your contributions will be dual-licensed under
the [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE) licenses, matching the
project.
