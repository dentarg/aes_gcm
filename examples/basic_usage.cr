require "../src/aes_gcm"

puts "=== AES-GCM Encryption Example ==="
puts

# Create a cipher instance
cipher = AesGcm::Cipher.new

# Your 32-byte (256-bit) encryption key
key = "12345678901234567890123456789012"
plaintext = "Hello, World! This is a secret message."

puts "Original message: #{plaintext}"
puts

# Encrypt
encrypted = cipher.encrypt(
  key: key,
  plaintext: plaintext
)

puts "Encrypted data:"
puts "  IV (hex):       #{encrypted.iv.hexstring}"
puts "  Auth Tag (hex): #{encrypted.auth_tag.hexstring}"
puts "  Ciphertext:     #{encrypted.ciphertext.hexstring}"
puts "  Base64:         #{encrypted.to_base64}"
puts

# Decrypt
decrypted = cipher.decrypt(encrypted)
puts "Decrypted message: #{String.new(decrypted)}"
puts

# Using base64 encoding
puts "=== Using Base64 Encoding ==="
encoded = cipher.encrypt_base64(key: key, plaintext: plaintext)
puts "Encoded: #{encoded}"

decoded = cipher.decrypt_base64(encoded: encoded, key: key)
puts "Decoded: #{String.new(decoded)}"
puts

# Example with wrong key (will fail)
puts "=== Testing Authentication (Wrong Key) ==="
wrong_key = "00000000000000000000000000000000"

begin
  cipher.decrypt(
    key: wrong_key,
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    auth_tag: encrypted.auth_tag
  )
  puts "ERROR: Should have failed with wrong key!"
rescue ex : OpenSSL::Cipher::Error
  puts "✓ Correctly rejected wrong key: #{ex.message}"
end
