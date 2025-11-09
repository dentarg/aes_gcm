# Sequel Column Encryption Support

This shard includes built-in support for decrypting data encrypted with Ruby's `sequel-column-encryption` gem.

## Quick Example

```crystal
require "aes_gcm"

key = ENV["SEQUEL_COLUMN_ENCRYPTION_KEY"]
encrypted = "AAAAAM4LImpq..." # Your encrypted column data

# One line to decrypt!
plaintext = AesGcm::SequelColumnEncryption.decrypt(encrypted, key)
```

## What is Sequel Column Encryption?

[sequel-column-encryption](https://github.com/aaronvegh/sequel-column-encryption) is a Ruby gem that provides transparent AES-256-GCM encryption for Sequel database columns. It's commonly used to encrypt sensitive data like:

- Personal Identifiable Information (PII)
- Credit card numbers
- Social Security numbers
- Email addresses
- Phone numbers

## Format Support

This shard supports all three Sequel column encryption formats:

1. **NOT_SEARCHABLE** (flag: 0) - Standard encryption, not searchable
2. **SEARCHABLE** (flag: 1) - Includes HMAC for exact-match searches
3. **LOWERCASE_SEARCHABLE** (flag: 2) - Includes lowercase HMAC for case-insensitive searches

## API

### Simple Decryption

```crystal
plaintext = AesGcm::SequelColumnEncryption.decrypt(encrypted_data, key)
```

**Parameters:**
- `encrypted_data` (String): Base64-encoded encrypted column data
- `key` (String | Bytes): Your encryption key (the master key, not derived)
- `remove_padding` (Bool, optional): Remove Sequel padding (default: true)

**Returns:** Decrypted plaintext as String

**Raises:** `AesGcm::SequelColumnEncryption::DecryptionError` if:
- Invalid base64 encoding
- Invalid encryption format
- Wrong encryption key
- Data is corrupted
- Invalid padding

### Decryption with Metadata

```crystal
info = AesGcm::SequelColumnEncryption.decrypt_with_info(encrypted_data, key)

puts info[:plaintext]  # Decrypted text
puts info[:format]     # "not_searchable", "searchable", or "lowercase_searchable"
puts info[:searchable] # true if searchable format
puts info[:key_id]     # Key ID used for encryption
puts info[:flags]      # Raw flags byte
```

### Format Validation

Check if data is in valid Sequel format without attempting decryption:

```crystal
if AesGcm::SequelColumnEncryption.valid_format?(data)
  # Data appears to be valid Sequel encrypted data
  plaintext = AesGcm::SequelColumnEncryption.decrypt(data, key)
end
```

## How It Works

The Sequel column encryption format includes:

1. **Header** (4 bytes):
   - Byte 0: Flags (0=not_searchable, 1=searchable, 2=lowercase_searchable)
   - Byte 1: Version
   - Byte 2: Key ID (for key rotation support)
   - Byte 3: Reserved

2. **Optional Search HMAC** (32 bytes, only for searchable formats):
   - HMAC-SHA256 of plaintext for searching

3. **Key Part** (32 bytes):
   - Random bytes used to derive the actual cipher key

4. **IV** (12 bytes):
   - Initialization vector for GCM

5. **Auth Tag** (16 bytes):
   - GCM authentication tag

6. **Ciphertext** (variable length):
   - The encrypted data with Sequel padding

## Key Derivation

The actual cipher key is derived using:

```crystal
cipher_key = HMAC-SHA256(master_key, key_part)
```

This allows key rotation without re-encrypting all data.

## Padding

Sequel adds random padding (0-7 bytes) to the beginning of plaintext before encryption. The first byte indicates the padding length. This shard automatically removes this padding by default.

## Migration from Ruby

If you're migrating from Ruby to Crystal:

**Ruby:**
```ruby
require 'sequel/extensions/column_encryption'

key = ENV['SEQUEL_COLUMN_ENCRYPTION_KEY']
encrypted_column = user[:encrypted_ssn]

# Sequel automatically decrypts on access
plaintext = user.ssn
```

**Crystal (with this shard):**
```crystal
require "aes_gcm"

key = ENV["SEQUEL_COLUMN_ENCRYPTION_KEY"]
encrypted_column = user["encrypted_ssn"].as(String)

# Explicit decryption
plaintext = AesGcm::SequelColumnEncryption.decrypt(encrypted_column, key)
```

## Security Considerations

1. **Key Storage**: Never hardcode keys. Use environment variables or a secure key management system.

2. **Key Rotation**: The format supports key rotation via the `key_id` field. Your application needs to maintain multiple keys and try them based on key_id.

3. **Authentication**: GCM mode provides authentication. If decryption fails, the data was either:
   - Encrypted with a different key
   - Tampered with
   - Corrupted

4. **Search HMACs**: For searchable formats, the HMAC allows exact-match database searches without decryption. This is intentional but means:
   - Exact values can be searched
   - Frequency analysis is possible
   - Use only when necessary

## Error Handling

```crystal
begin
  plaintext = AesGcm::SequelColumnEncryption.decrypt(encrypted, key)
rescue ex : AesGcm::SequelColumnEncryption::DecryptionError
  # Handle decryption errors
  STDERR.puts "Decryption failed: #{ex.message}"
end
```

Common error messages:
- "Invalid base64 encoding" - Data is not valid base64
- "Encrypted data too small" - Data is truncated or invalid
- "Invalid encryption flags" - Unknown format
- "Decryption failed: ... (check encryption key)" - Wrong key or corrupted data
- "Invalid padding length" - Corrupted plaintext padding

## Performance

Decryption is fast due to:
- Direct OpenSSL C bindings
- No unnecessary copies
- Efficient base64 decoding

Typical performance: ~0.1ms per decryption on modern hardware.

## Testing

The shard includes comprehensive tests with real Sequel-encrypted data:

```bash
crystal spec
# 29 examples, 0 failures
```

## Examples

See `examples/sequel_column_encryption.cr` for a complete working example.

## Related Documentation

- [Main README](README.md)
- [Quick Start Guide](QUICKSTART.md)
- [Sequel Column Encryption Gem](https://github.com/aaronvegh/sequel-column-encryption)
