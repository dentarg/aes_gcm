# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-11-09

### Added
- Initial release of AES-GCM shard
- AES-256-GCM encryption and decryption support
- Authentication tag support via direct OpenSSL C bindings
- Base64 encoding/decoding helpers
- `EncryptedData` struct for managing encrypted data components
- Comprehensive test suite (11 specs)
- Examples for basic usage and Sequel column encryption
- Full documentation with security best practices

### Fixed
- Removed `@[Link("crypto")]` annotation to prevent "duplicate libraries" warning on macOS
  - Crystal's OpenSSL module already links libcrypto, so explicit linking was redundant

### Technical Details
- Uses direct C bindings to `EVP_CIPHER_CTX_ctrl` for GCM operations
- Supports custom IV sizes (default: 12 bytes)
- Supports custom authentication tag sizes (default: 16 bytes)
- Generates cryptographically secure random IVs by default

### Known Limitations
- Limited AAD (Additional Authenticated Data) support due to Crystal's OpenSSL wrapper
- Only supports AES-256-GCM (not AES-128-GCM or AES-192-GCM)

## [Unreleased]

### Planned
- Full AAD support with custom C bindings
- Support for AES-128-GCM and AES-192-GCM variants
- Streaming encryption/decryption for large files
- Performance benchmarks
