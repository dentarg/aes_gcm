# AES-GCM Crystal Shard

A Crystal shard providing AES-256-GCM (Galois/Counter Mode) authenticated encryption and decryption.

## Features

- ✅ AES-256-GCM encryption and decryption
- ✅ Authentication tag support (protects against tampering)
- ✅ Configurable IV and tag sizes
- ✅ Base64 encoding/decoding helpers
- ✅ Direct bindings to OpenSSL for full GCM support
- ✅ Type-safe API with Crystal's type system

## Why This Shard?

Crystal's standard `OpenSSL::Cipher` library doesn't expose methods to get/set authentication tags for GCM mode. This shard provides direct bindings to OpenSSL's `EVP_CIPHER_CTX_ctrl` function to enable full GCM functionality.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  aes_gcm:
    path: ./shard
```

Then run:

```bash
shards install
```

## Usage

### Basic Encryption/Decryption

```crystal
require "aes_gcm"

cipher = AesGcm::Cipher.new

# Your 32-byte (256-bit) encryption key
key = "12345678901234567890123456789012"
plaintext = "Hello, World!"

# Encrypt
encrypted = cipher.encrypt(
  key: key,
  plaintext: plaintext
)

# Access encrypted components
puts encrypted.iv.hexstring        # Initialization vector
puts encrypted.auth_tag.hexstring  # Authentication tag
puts encrypted.ciphertext.hexstring # Encrypted data

# Decrypt
decrypted = cipher.decrypt(encrypted)
puts String.new(decrypted)  # "Hello, World!"
```

### Base64 Encoding

```crystal
cipher = AesGcm::Cipher.new
key = "12345678901234567890123456789012"

# Encrypt and encode to base64
encoded = cipher.encrypt_base64(
  key: key,
  plaintext: "secret message"
)

# Decrypt from base64
decoded = cipher.decrypt_base64(
  encoded: encoded,
  key: key
)
puts String.new(decoded)
```

### Additional Authenticated Data (AAD)

*Note: AAD support is limited in the current version due to Crystal's OpenSSL wrapper limitations.*

```crystal
# Future API (not fully implemented yet)
encrypted = cipher.encrypt(
  key: key,
  plaintext: "secret",
  aad: "metadata"
)

decrypted = cipher.decrypt(
  encrypted,
  aad: "metadata"  # Must match encryption AAD
)
```

### Custom Configuration

```crystal
# Custom IV and tag sizes
cipher = AesGcm::Cipher.new(
  iv_size: 12,   # 96-bit IV (default)
  tag_size: 16,  # 128-bit tag (default)
  key_size: 32   # 256-bit key (default)
)
```

## API Documentation

### `AesGcm::Cipher`

Main cipher class for AES-256-GCM operations.

#### Methods

- `encrypt(key, plaintext, iv = nil, aad = "") : EncryptedData`
  - Encrypts plaintext and returns encrypted data with IV and auth tag
  - `key`: 32-byte encryption key (String or Bytes)
  - `plaintext`: Data to encrypt (String or Bytes)
  - `iv`: Optional IV (defaults to random)
  - `aad`: Additional authenticated data (not yet fully supported)

- `decrypt(key, ciphertext, iv, auth_tag, aad = "") : Bytes`
  - Decrypts ciphertext and verifies authenticity
  - Raises `OpenSSL::Cipher::Error` if authentication fails

- `decrypt(encrypted : EncryptedData, aad = "") : Bytes`
  - Convenience method to decrypt from EncryptedData struct

- `encrypt_base64(key, plaintext, aad = "") : String`
  - Encrypts and returns URL-safe base64 encoded string

- `decrypt_base64(encoded, key, aad = "") : Bytes`
  - Decrypts from URL-safe base64 encoded string

### `AesGcm::EncryptedData`

Struct containing all components needed for decryption.

#### Properties

- `ciphertext : Bytes` - Encrypted data
- `iv : Bytes` - Initialization vector
- `auth_tag : Bytes` - Authentication tag
- `key : Bytes` - Encryption key

#### Methods

- `to_base64 : String` - Encode all components to URL-safe base64
- `self.from_base64(encoded, key, iv_size = 12, tag_size = 16) : EncryptedData`

## Security Notes

1. **Key Management**: Never hardcode encryption keys in your source code. Use environment variables or secure key management systems.

2. **Authentication**: GCM mode provides authenticated encryption. If decryption fails with a `OpenSSL::Cipher::Error`, it means:
   - The data was tampered with
   - Wrong encryption key was used
   - Wrong AAD was used
   - Data is corrupted

3. **IV Reuse**: Never reuse the same IV with the same key. This implementation generates random IVs by default.

4. **Key Size**: This shard uses AES-256 (32-byte keys). Ensure your keys have sufficient entropy.

## Examples

See the `examples/` directory for more examples:

- `basic_usage.cr` - Basic encryption/decryption examples
- `sequel_column_encryption.cr` - Decrypting Sequel column encryption format

Run examples:

```bash
cd shard
crystal run examples/basic_usage.cr
crystal run examples/sequel_column_encryption.cr
```

## Technical Details

This shard uses direct C bindings to OpenSSL's `EVP_CIPHER_CTX_ctrl` function to access GCM-specific operations:

- `EVP_CTRL_GCM_SET_TAG` (0x11) - Set authentication tag for decryption
- `EVP_CTRL_GCM_GET_TAG` (0x10) - Get authentication tag after encryption
- `EVP_CTRL_GCM_SET_IVLEN` (0x9) - Set custom IV length

**Note on Linking**: We don't use `@[Link("crypto")]` in our C bindings because Crystal's OpenSSL module already links to libcrypto. Adding it would cause duplicate library warnings on macOS and other platforms.

## Limitations

1. **AAD Support**: Additional Authenticated Data (AAD) support is limited in the current version due to Crystal's OpenSSL wrapper not exposing the necessary update methods.

2. **Algorithm**: Only AES-256-GCM is supported. Other GCM variants (AES-128-GCM, AES-192-GCM) could be added in future versions.

## Troubleshooting

### "ld: warning: ignoring duplicate libraries: '-lcrypto'" on macOS

This warning has been fixed in version 0.1.0. If you see this warning in older versions, it's because Crystal's OpenSSL module already links to libcrypto. The warning is harmless but can be fixed by removing the `@[Link("crypto")]` annotation.

### Decryption fails with "authentication verification failed"

This error means:
- Wrong encryption key
- Data has been tampered with
- Wrong AAD was used
- Corrupted ciphertext or auth tag

Double-check your key and ensure the same AAD is used for both encryption and decryption.

### "Key must be 32 bytes" error

AES-256 requires exactly 32 bytes (256 bits) for the key. Ensure your key string is exactly 32 bytes:

```crystal
key = "12345678901234567890123456789012"  # Exactly 32 bytes
puts key.bytesize  # Should print 32
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License

## Credits

Inspired by the need to decrypt Sequel column encryption data in Crystal.
