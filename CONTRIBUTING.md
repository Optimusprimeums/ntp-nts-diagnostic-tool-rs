# Contributing

Contributions are welcome.

1. Fork the repository and create a focused branch.
2. Keep protocol-engine changes separate from UI-only changes where practical.
3. Do not log NTS keys, private keys, or other secrets.
4. Test NTP-only mode and NTS mode.
5. For NTS protocol changes, test against an independent implementation.
6. Run `cargo fmt`, `cargo clippy --all-targets` and `cargo test`, and a `cargo build --release` before submitting release-related changes.
7. Describe interoperability results and security-relevant behavior changes in the pull request.

Version 3.x (Rust) is validated against `time.cloudflare.com` and two ESP32-P4 NTS servers; 2.0.2 (Python) is the previous known-good baseline.

User documentation lives in `docs/wiki` and the website in `docs/site`. Change them in the same pull request as the behaviour they describe; each release publishes them.
