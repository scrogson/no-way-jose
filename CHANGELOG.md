# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-02-05

### Added

- SSL/TLS configuration support for JWKS fetcher via `connect_options`. This enables
  configuring certificate verification for development/staging environments with
  self-signed certificates. ([#9](https://github.com/scrogson/no-way-jose/pull/9))

### Changed

- Bump `rsa` crate from 0.9.9 to 0.9.10

## [1.0.1] - 2025-12-31

### Fixed

- Disable audience validation when no expected audience is provided. Previously,
  tokens with an `aud` claim would fail verification if no `aud` option was
  passed, due to jsonwebtoken v10 defaulting `validate_aud` to `true`.

## [1.0.0] - 2025-12-30

### Breaking Changes

- **API redesign**: The entire public API has been redesigned for clarity and consistency
- **Key struct**: Keys are now wrapped in `NoWayJose.Key` struct instead of raw binaries
- **Function signatures changed**:
  - `sign(key, claims)` instead of `sign(claims, key: key, ...)`
  - `verify(key, token)` instead of separate verification functions
  - Key is now the first argument for better pipe compatibility

### Added

- **Algorithm support**: RS256, RS384, RS512, PS256, PS384, PS512, ES256 (P-256), ES384 (P-384)
- **Key generation**: `generate/2` for creating RSA and EC key pairs
- **Key import**: `import/3` for loading keys from PEM, DER, JWK, or JWKS formats
- **Key export**: `export/2` for exporting public keys as JWK, PEM, or DER
- **JWT verification**: `verify/3` with configurable claims validation
- **Validation options**:
  - `validate_exp` - Validate expiration claim
  - `validate_nbf` - Validate not-before claim
  - `leeway` - Clock skew tolerance in seconds
  - `iss` - Required issuer(s)
  - `aud` - Required audience(s)
  - `sub` - Required subject
  - `required_claims` - List of required claim names
- **JWKS fetcher**: Auto-refreshing key fetcher for external identity providers
  - `start_jwks_fetcher/3` and `stop_jwks_fetcher/1`
  - `verify_with_stored/3` for verifying with fetched keys
- **Key store**: In-memory key storage for managing multiple keys
  - `put_key/2`, `get_key/2`, `get_keys/1`, `delete_keys/1`
- **JWKS export**: `export_jwks/1` for serving `.well-known/jwks.json`
- **Header decoding**: `decode_header/1` for extracting JWT headers without verification
- **Bang variants**: `sign!/3`, `verify!/3`, `decode_header!/1`, etc.

### Changed

- Upgraded to Rustler 0.37
- Updated all Rust dependencies

### Removed

- `sign/2` with keyword options (replaced by `sign/3` with Key struct)
- `generate_rsa/2` returning raw PEM/DER (replaced by `generate/2`)

## [0.3.0] - 2024-01-05

### Changed

- Removed OpenSSL dependency, now uses pure Rust `rsa` crate
- Updated to modern Rustler and NIF versions
- Replaced `Logger.warn` with `Logger.warning`

### Fixed

- musl builds now use `-crt-static`

## [0.2.0] - 2020-07-24

### Added

- `generate_rsa/2` for generating RSA key pairs

## [0.1.0] - 2020-03-05

### Added

- Initial release
- RS512 JWT signing
- PEM and DER key format support
