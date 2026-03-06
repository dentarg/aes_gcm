require "../src/aes_gcm"

# Example: Decrypting Sequel column encryption format
# This demonstrates how to use the AesGcm shard to decrypt data
# encrypted in the Sequel column encryption format.

puts "=== Sequel Column Encryption Decryption Example ==="
puts

key = ENV.fetch("SEQUEL_COLUMN_ENCRYPTION_KEY", "24cd14f11f67153c9102df8d58e94b26")
encrypted_data = "AAAAAM4LImpqpydSaTW4xW8P9EbeUA36hfElspicYl1HFDFM2sQATqr78uijno5RwJiTITMppEkpkbN_alpFOQOi77QgaJViniquDav9fibs"

puts "Encrypted (base64): #{encrypted_data[0...40]}..."
puts

# Simple decryption
decrypted = AesGcm::SequelColumnEncryption.decrypt(encrypted_data, key)
puts "Decrypted plaintext: #{decrypted}"
puts

# Decryption with metadata
puts "=== With Metadata ==="
info = AesGcm::SequelColumnEncryption.decrypt_with_info(encrypted_data, key)
puts "Plaintext: #{info[:plaintext]}"
puts "Format: #{info[:format]}"
puts "Searchable: #{info[:searchable]}"
puts "Key ID: #{info[:key_id]}"
puts "Flags: #{info[:flags]}"
puts

# Validate format
puts "=== Format Validation ==="
if AesGcm::SequelColumnEncryption.valid_format?(encrypted_data)
  puts "✓ Data is in valid Sequel column encryption format"
else
  puts "✗ Data is not in Sequel format"
end
