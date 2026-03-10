require "openssl"
require "openssl/hmac"
require "base64"
require "./aes_gcm/sequel_column_encryption"

# AES-GCM authenticated encryption/decryption module
#
# This module provides support for AES-256-GCM (Galois/Counter Mode) encryption,
# which provides both confidentiality and authenticity. Crystal's standard library
# doesn't expose GCM authentication tag methods, so this module uses direct
# bindings to OpenSSL's C library.
#
# Example:
# ```
# cipher = AesGcm::Cipher.new
#
# # Encryption
# encrypted = cipher.encrypt(
#   key: "32_byte_key_here_____________",
#   plaintext: "secret message"
# )
#
# # Decryption
# decrypted = cipher.decrypt(encrypted, key: "32_byte_key_here_____________")
# ```
module AesGcm
  VERSION = "0.1.0"

  # Low-level bindings to OpenSSL's EVP_CIPHER_CTX_ctrl function
  # Note: We don't need @[Link("crypto")] here because Crystal's OpenSSL module
  # already links to libcrypto. Adding it would cause duplicate library warnings.
  lib LibCrypto
    EVP_CTRL_GCM_SET_TAG = 0x11
    EVP_CTRL_GCM_GET_TAG = 0x10

    fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(
      ctx : Void*,
      type : Int32,
      arg : Int32,
      ptr : Void*,
    ) : Int32
  end

  # Represents encrypted data with all necessary components for decryption.
  # The key is intentionally not stored here — pass it explicitly to decrypt.
  struct EncryptedData
    property ciphertext : Bytes
    property iv : Bytes
    property auth_tag : Bytes

    def initialize(@ciphertext, @iv, @auth_tag)
    end

    # Convert to URL-safe base64 encoded string (all components concatenated)
    def to_base64 : String
      combined = IO::Memory.new
      combined.write(iv)
      combined.write(auth_tag)
      combined.write(ciphertext)
      Base64.urlsafe_encode(combined.to_slice, padding: false)
    end

    # Parse from URL-safe base64 encoded string
    def self.from_base64(encoded : String, iv_size : Int32 = 12, tag_size : Int32 = 16) : EncryptedData
      data = Base64.decode(encoded.tr("-_", "+/"))

      if data.size < iv_size + tag_size
        raise ArgumentError.new("Encoded data too small")
      end

      iv = data[0, iv_size]
      auth_tag = data[iv_size, tag_size]
      ciphertext = data[iv_size + tag_size..]

      new(ciphertext, iv, auth_tag)
    end
  end

  # Main cipher class for AES-256-GCM operations
  class Cipher
    property iv_size : Int32 = 12  # 96-bit IV (recommended for GCM)
    property tag_size : Int32 = 16 # 128-bit tag
    property key_size : Int32 = 32 # 256-bit key

    def initialize(@iv_size = 12, @tag_size = 16, @key_size = 32)
    end

    # Encrypt plaintext using AES-256-GCM
    #
    # Parameters:
    # - key: 32-byte encryption key (String or Bytes)
    # - plaintext: Data to encrypt (String or Bytes)
    # - iv: Optional initialization vector (defaults to random)
    #
    # Returns: EncryptedData containing ciphertext, iv, and auth_tag
    def encrypt(
      key : String | Bytes,
      plaintext : String | Bytes,
      iv : Bytes? = nil,
    ) : EncryptedData
      # Convert inputs to bytes
      key_bytes = key.is_a?(String) ? key.to_slice : key
      plaintext_bytes = plaintext.is_a?(String) ? plaintext.to_slice : plaintext

      # Validate key size
      if key_bytes.size != @key_size
        raise ArgumentError.new("Key must be #{@key_size} bytes, got #{key_bytes.size}")
      end

      # Generate random IV if not provided
      iv_bytes = iv || Random::Secure.random_bytes(@iv_size)

      # Create and configure cipher
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.encrypt
      cipher.key = key_bytes
      cipher.iv = iv_bytes

      # Encrypt
      ciphertext = IO::Memory.new
      ciphertext.write(cipher.update(plaintext_bytes))
      ciphertext.write(cipher.final)

      # Get authentication tag
      auth_tag = get_auth_tag(cipher, @tag_size)

      EncryptedData.new(
        ciphertext: ciphertext.to_slice,
        iv: iv_bytes,
        auth_tag: auth_tag
      )
    end

    # Decrypt ciphertext using AES-256-GCM
    #
    # Parameters:
    # - key: 32-byte encryption key (String or Bytes)
    # - ciphertext: Encrypted data (Bytes)
    # - iv: Initialization vector used during encryption
    # - auth_tag: Authentication tag from encryption
    #
    # Returns: Decrypted data as Bytes
    # Raises: OpenSSL::Cipher::Error if authentication fails or data is corrupted
    def decrypt(
      key : String | Bytes,
      ciphertext : Bytes,
      iv : Bytes,
      auth_tag : Bytes,
    ) : Bytes
      # Convert inputs to bytes
      key_bytes = key.is_a?(String) ? key.to_slice : key

      # Validate key size
      if key_bytes.size != @key_size
        raise ArgumentError.new("Key must be #{@key_size} bytes, got #{key_bytes.size}")
      end

      # Create and configure cipher
      cipher = OpenSSL::Cipher.new("aes-256-gcm")
      cipher.decrypt
      cipher.key = key_bytes
      cipher.iv = iv

      # Set authentication tag (must be done before decryption)
      set_auth_tag(cipher, auth_tag)

      # Decrypt
      begin
        plaintext = IO::Memory.new
        plaintext.write(cipher.update(ciphertext))
        plaintext.write(cipher.final)
        plaintext.to_slice
      rescue ex : OpenSSL::Cipher::Error
        raise OpenSSL::Cipher::Error.new(
          "Decryption failed: authentication verification failed (corrupted data or wrong key)"
        )
      end
    end

    # Decrypt from EncryptedData struct
    def decrypt(encrypted : EncryptedData, key : String | Bytes) : Bytes
      decrypt(
        key: key,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        auth_tag: encrypted.auth_tag
      )
    end

    # Helper method to encrypt and return base64-encoded string
    def encrypt_base64(
      key : String | Bytes,
      plaintext : String | Bytes,
    ) : String
      encrypted = encrypt(key: key, plaintext: plaintext)
      encrypted.to_base64
    end

    # Helper method to decrypt from base64-encoded string
    def decrypt_base64(
      encoded : String,
      key : String | Bytes,
    ) : Bytes
      encrypted = EncryptedData.from_base64(encoded, @iv_size, @tag_size)
      decrypt(encrypted, key)
    end

    # Set the authentication tag on the cipher (for decryption)
    private def set_auth_tag(cipher : OpenSSL::Cipher, tag : Bytes) : Nil
      ctx_ptr = cipher.@ctx
      result = LibCrypto.evp_cipher_ctx_ctrl(
        ctx_ptr,
        LibCrypto::EVP_CTRL_GCM_SET_TAG,
        tag.size,
        tag.to_unsafe.as(Void*)
      )

      if result != 1
        raise OpenSSL::Cipher::Error.new("Failed to set GCM authentication tag")
      end
    end

    # Get the authentication tag from the cipher (after encryption)
    private def get_auth_tag(cipher : OpenSSL::Cipher, tag_size : Int32) : Bytes
      tag = Bytes.new(tag_size)
      ctx_ptr = cipher.@ctx
      result = LibCrypto.evp_cipher_ctx_ctrl(
        ctx_ptr,
        LibCrypto::EVP_CTRL_GCM_GET_TAG,
        tag_size,
        tag.to_unsafe.as(Void*)
      )

      if result != 1
        raise OpenSSL::Cipher::Error.new("Failed to get GCM authentication tag")
      end

      tag
    end
  end
end
