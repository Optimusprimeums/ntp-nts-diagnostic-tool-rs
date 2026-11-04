# Contributing

Contributions are welcome.

1. Fork the repository and create a focused branch.
2. Keep protocol-engine changes separate from UI-only changes where practical.
3. Do not log NTS keys, private keys, or other secrets.
4. Test NTP-only mode and NTS mode.
5. For NTS protocol changes, test against an independent implementation.
6. Run `cargo fmt`, `cargo clippy --all-targets` and `cargo test`, and a `cargo build --release` before submitting release-related changes.
7. Describe interoperability results and security-relevant behavior changes in the pull request.

Version 3.0.0 (Rust) is validated against `time.cloudflare.com`; 2.0.2 (Python) is the previous known-good baseline.
