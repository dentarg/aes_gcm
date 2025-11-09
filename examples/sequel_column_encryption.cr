require "../src/aes_gcm"
require "openssl/hmac"
require "base64"

# Example: Decrypting Sequel column encryption format
# This demonstrates how to use the AesGcm shard to decrypt data
# encrypted in the Sequel column encryption format.

module SequelColumnEncryption
  NOT_SEARCHABLE       = 0
  SEARCHABLE           = 1
  LOWERCASE_SEARCHABLE = 2

  # Decrypt data in Sequel column encryption format
  def self.decrypt(data_base64 : String, key : String) : String
    # Decode from URL-safe base64
    data = Base64.decode(data_base64.tr("-_", "+/"))

    # Parse header
    flags = data[0]
    key_id = data[2]

    # Determine offset based on flags
    offset = case flags
             when NOT_SEARCHABLE
               raise "Data too small" if data.size < 65
               4
             when SEARCHABLE, LOWERCASE_SEARCHABLE
               raise "Data too small" if data.size < 97
               36
             else
               raise "Invalid flags: #{flags}"
             end

    # Extract components
    key_part = data[offset, 32]
    cipher_iv = data[offset + 32, 12]
    auth_tag = data[offset + 44, 16]
    ciphertext = data[offset + 60..]

    # Derive cipher key using HMAC-SHA256
    cipher_key = OpenSSL::HMAC.digest(:sha256, key, key_part)

    # Decrypt using AES-GCM
    cipher = AesGcm::Cipher.new
    decrypted_bytes = cipher.decrypt(
      key: cipher_key,
      ciphertext: ciphertext,
      iv: cipher_iv,
      auth_tag: auth_tag
    )

    # Remove padding
    padding_length = decrypted_bytes[0]
    final_data = decrypted_bytes[padding_length + 1..]

    String.new(final_data)
  end
end

# Example usage
puts "=== Sequel Column Encryption Decryption Example ==="
puts

key = ENV.fetch("SEQUEL_COLUMN_ENCRYPTION_KEY", "24cd14f11f67153c9102df8d58e94b26")
encrypted_data = "AAAAAM4LImpqpydSaTW4xW8P9EbeUA36hfElspicYl1HFDFM2sQATqr78uijno5RwJiTITMppEkpkbN_alpFOQOi77QgaJViniquDav9fibs"

puts "Encrypted (base64): #{encrypted_data[0...40]}..."
puts

decrypted = SequelColumnEncryption.decrypt(encrypted_data, key)
puts "Decrypted plaintext: #{decrypted}"
