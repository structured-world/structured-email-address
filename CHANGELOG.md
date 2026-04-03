# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2](https://github.com/structured-world/structured-email-address/compare/v0.0.1...v0.0.2) - 2026-04-03

### Added

- batch parsing API for bulk import/validation ([#19](https://github.com/structured-world/structured-email-address/pull/19))
- initial implementation — RFC 5322/6531 email parser, normalizer, validator ([#11](https://github.com/structured-world/structured-email-address/pull/11))

### Fixed

- strict mode (RFC 5321) rejects quoted-strings and comments ([#25](https://github.com/structured-world/structured-email-address/pull/25))
