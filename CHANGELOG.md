# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.12](https://github.com/structured-world/structured-email-address/compare/v0.0.11...v0.0.12) - 2026-07-02

### Data

PSL data: bump structured-public-domains to v0.0.13.

## [0.0.11](https://github.com/structured-world/structured-email-address/compare/v0.0.10...v0.0.11) - 2026-06-30

### Testing

- move inline test modules to sibling files ([#59](https://github.com/structured-world/structured-email-address/pull/59))

## [0.0.10](https://github.com/structured-world/structured-email-address/compare/v0.0.9...v0.0.10) - 2026-06-30

### Data

PSL data: bump structured-public-domains to v0.0.12.

## [0.0.9](https://github.com/structured-world/structured-email-address/compare/v0.0.8...v0.0.9) - 2026-06-29

### Added

- *(normalize)* extensible provider registry ([#52](https://github.com/structured-world/structured-email-address/pull/52))

## [0.0.8](https://github.com/structured-world/structured-email-address/compare/v0.0.7...v0.0.8) - 2026-06-28

### Data

PSL data: bump structured-public-domains to v0.0.10.

## [0.0.7](https://github.com/structured-world/structured-email-address/compare/v0.0.6...v0.0.7) - 2026-06-28

### Added

- *(deps)* migrate PSL to structured-public-domains + cascade releases ([#48](https://github.com/structured-world/structured-email-address/pull/48))

## [0.0.6](https://github.com/structured-world/structured-email-address/compare/v0.0.5...v0.0.6) - 2026-06-23

### Fixed

- *(parser)* harden RFC 5321/5322 conformance (CFWS, CR/LF, IP literals) ([#45](https://github.com/structured-world/structured-email-address/pull/45))

## [0.0.4](https://github.com/structured-world/structured-email-address/compare/v0.0.3...v0.0.4) - 2026-04-04

### Fixed

- *(parser)* strip CFWS from obs-local-part and obs-domain spans ([#32](https://github.com/structured-world/structured-email-address/pull/32))

## [0.0.3](https://github.com/structured-world/structured-email-address/compare/v0.0.2...v0.0.3) - 2026-04-03

### Documentation

- add IDN homograph safety note to domain_unicode() ([#30](https://github.com/structured-world/structured-email-address/pull/30))

## [0.0.2](https://github.com/structured-world/structured-email-address/compare/v0.0.1...v0.0.2) - 2026-04-03

### Added

- batch parsing API for bulk import/validation ([#19](https://github.com/structured-world/structured-email-address/pull/19))
- initial implementation — RFC 5322/6531 email parser, normalizer, validator ([#11](https://github.com/structured-world/structured-email-address/pull/11))

### Fixed

- strict mode (RFC 5321) rejects quoted-strings and comments ([#25](https://github.com/structured-world/structured-email-address/pull/25))
