# GitHub Copilot Instructions for structured-email-address

## Project Overview

RFC 5321/5322/6531 email address parser, validator, and normalizer for Rust. Features subaddress extraction, provider-aware normalization, PSL domain validation, and anti-homoglyph protection.

## Review Scope Rules

**Review ONLY code within the PR's diff.** For issues found outside the diff, suggest creating a separate issue.

**Each PR has a defined scope.** Read the description before reviewing. If something is listed as out of scope, do not flag it.

## Rust Code Standards

- **No `unwrap()` or `expect()`** on any code path: `#[deny(clippy::unwrap_used, clippy::expect_used)]` is enforced crate-wide
- **Clippy:** Must pass `cargo clippy --all-features -- -D warnings`
- **Feature gates:** `serde` and `psl` are optional features. Code must compile with `--no-default-features`
- **Error handling:** All parse/validate errors return typed `Error` with `ErrorKind` and byte position

## Testing Standards

- RFC conformance: isEmail test suite (1226 edge cases) is the conformance baseline
- All normalization paths must have tests for edge cases (Unicode NFC, IDNA, confusables)
- Feature-gated code must be tested both with and without the feature
