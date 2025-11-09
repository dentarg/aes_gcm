# Quick Start Guide

## Installation

The shard is located in the `/app/shard` directory. To use it in your Crystal project:

1. Add to your `shard.yml`:
```yaml
dependencies:
  aes_gcm:
    path: /app/shard
```

2. Run `shards install`

## Basic Usage

### Sequel Column Encryption (Most Common)

If you're migrating from Ruby and need to decrypt sequel-column-encryption data:

```crystal
require "aes_gcm"

key = ENV["SEQUEL_COLUMN_ENCRYPTION_KEY"]
encrypted = "AAAAAM4LImpq..." # Your encrypted data

# Simple one-liner
plaintext = AesGcm::SequelColumnEncryption.decrypt(encrypted, key)
puts plaintext  # => "John Doe"
```

### General AES-256-GCM Encryption

```crystal
require "aes_gcm"

# Create a cipher instance
cipher = AesGcm::Cipher.new

# Your 32-byte encryption key
key = "12345678901234567890123456789012"

# Encrypt
encrypted = cipher.encrypt(
  key: key,
  plaintext: "Secret message"
)

# Decrypt
decrypted = cipher.decrypt(encrypted)
puts String.new(decrypted)  # "Secret message"
```

## Run Examples

```bash
# Basic usage example
cd /app/shard
crystal run examples/basic_usage.cr

# Sequel column encryption example
SEQUEL_COLUMN_ENCRYPTION_KEY="your_key" crystal run examples/sequel_column_encryption.cr
```

## Run Tests

```bash
cd /app/shard
crystal spec
```

## Key Features

✅ **AES-256-GCM** - Industry-standard authenticated encryption
✅ **Authentication** - Prevents tampering and forgery
✅ **Type-safe** - Leverages Crystal's type system
✅ **Base64 support** - Easy encoding/decoding
✅ **Random IVs** - Secure by default
✅ **Tested** - 11 comprehensive specs

## What is GCM?

GCM (Galois/Counter Mode) is an authenticated encryption mode that provides both:

1. **Confidentiality** - Data is encrypted and cannot be read without the key
2. **Authenticity** - Data cannot be tampered with or forged

When you decrypt with GCM:
- ✓ Wrong key → Decryption fails
- ✓ Tampered data → Decryption fails
- ✓ Wrong auth tag → Decryption fails

This is much more secure than CBC or ECB modes which only provide confidentiality.

## Common Use Cases

- **Database encryption** - Encrypt sensitive database fields
- **API tokens** - Create tamper-proof authentication tokens
- **File encryption** - Protect files with authenticated encryption
- **Message encryption** - Secure messaging between services

## Migration from Ruby

If you're migrating from Ruby's OpenSSL::Cipher, the API is very similar:

**Ruby:**
```ruby
cipher = OpenSSL::Cipher.new('aes-256-gcm')
cipher.encrypt
cipher.key = key
cipher.iv = iv
ciphertext = cipher.update(plaintext) + cipher.final
auth_tag = cipher.auth_tag
```

**Crystal (with this shard):**
```crystal
cipher = AesGcm::Cipher.new
encrypted = cipher.encrypt(key: key, plaintext: plaintext)
# encrypted contains: ciphertext, iv, auth_tag, key
```

## Security Best Practices

1. **Never reuse IVs** - This shard generates random IVs by default
2. **Use strong keys** - 32 bytes of random data from a CSPRNG
3. **Store keys securely** - Use environment variables or key management systems
4. **Verify authentication** - Always check for decryption errors
5. **Use HTTPS** - When transmitting encrypted data over networks

## Support

For issues or questions:
- Read the [full README](README.md)
- Check the [examples](examples/)
- Run the [specs](spec/)
