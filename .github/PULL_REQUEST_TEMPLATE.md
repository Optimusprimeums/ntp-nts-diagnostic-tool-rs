## Summary

Describe the change.

## Testing

- [ ] NTP-only mode tested
- [ ] NTS mode tested
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass
- [ ] Release executables tested on Windows
- [ ] Certificate verification remains enabled by default
- [ ] No secrets or NTS key material are logged

## Interoperability

Describe independent NTS implementation(s) tested if protocol behavior changed.
