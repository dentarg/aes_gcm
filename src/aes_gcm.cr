require "openssl"
require "openssl/hmac"
require "base64"

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
# decrypted = cipher.decrypt(
#   key: encrypted.key,
#   ciphertext: encrypted.ciphertext,
#   iv: encrypted.iv,
#   auth_tag: encrypted.auth_tag
# )
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

  # Represents encrypted data with all necessary components for decryption
  struct EncryptedData
    property ciphertext : Bytes
    property iv : Bytes
    property auth_tag : Bytes
    property key : Bytes

    def initialize(@ciphertext, @iv, @auth_tag, @key)
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
    def self.from_base64(encoded : String, key : String | Bytes, iv_size : Int32 = 12, tag_size : Int32 = 16) : EncryptedData
      data = Base64.decode(encoded.tr("-_", "+/"))

      if data.size < iv_size + tag_size
        raise ArgumentError.new("Encoded data too small")
      end

      iv = data[0, iv_size]
      auth_tag = data[iv_size, tag_size]
      ciphertext = data[iv_size + tag_size..]

      key_bytes = key.is_a?(String) ? key.to_slice : key

      new(ciphertext, iv, auth_tag, key_bytes)
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
    # Returns: EncryptedData containing ciphertext, iv, auth_tag, and key
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
        auth_tag: auth_tag,
        key: key_bytes
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
    def decrypt(encrypted : EncryptedData) : Bytes
      decrypt(
        key: encrypted.key,
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
      encrypted = EncryptedData.from_base64(encoded, key, @iv_size, @tag_size)
      decrypt(encrypted)
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

  # Module for decrypting data encrypted with the Sequel column encryption plugin
  #
  # This module provides utilities to decrypt data encrypted using Ruby's
  # sequel-column-encryption gem, which is commonly used for encrypting
  # database columns in Sequel ORM applications.
  #
  # Example:
  # ```
  # key = ENV["SEQUEL_COLUMN_ENCRYPTION_KEY"]
  # encrypted = "AAAAAM4LImpq..." # Base64 encoded encrypted data
  #
  # decrypted = AesGcm::SequelColumnEncryption.decrypt(encrypted, key)
  # puts decrypted # => "John Doe"
  # ```
  module SequelColumnEncryption
    # Encryption format flags
    NOT_SEARCHABLE       = 0_u8
    SEARCHABLE           = 1_u8
    LOWERCASE_SEARCHABLE = 2_u8

    # Minimum sizes for encrypted data based on format
    MIN_SIZE_NOT_SEARCHABLE = 65
    MIN_SIZE_SEARCHABLE     = 97

    # Component sizes
    KEY_PART_SIZE = 32
    IV_SIZE       = 12
    TAG_SIZE      = 16

    # Error raised when decryption fails
    class DecryptionError < Exception
    end

    # Decrypt data encrypted in Sequel column encryption format
    #
    # Parameters:
    # - data_base64: Base64-encoded encrypted data (String)
    # - key: Encryption key (String or Bytes)
    # - remove_padding: Whether to remove Sequel padding (default: true)
    #
    # Returns: Decrypted plaintext as String
    #
    # Raises: DecryptionError if data is invalid or decryption fails
    def self.decrypt(data_base64 : String, key : String | Bytes, remove_padding : Bool = true) : String
      begin
        data = decode_base64(data_base64)
      rescue ex
        raise DecryptionError.new("Invalid base64 encoding: #{ex.message}")
      end
      decrypt_bytes(data, key, remove_padding)
    end

    # Decrypt data and return detailed information about the encryption format
    #
    # Parameters:
    # - data_base64: Base64-encoded encrypted data (String)
    # - key: Encryption key (String or Bytes)
    #
    # Returns: NamedTuple with decrypted data and metadata
    def self.decrypt_with_info(data_base64 : String, key : String | Bytes) : NamedTuple(
      plaintext: String,
      flags: UInt8,
      key_id: UInt8,
      searchable: Bool,
      format: String)
      begin
        data = decode_base64(data_base64)
      rescue ex
        raise DecryptionError.new("Invalid base64 encoding: #{ex.message}")
      end

      flags = data[0]
      key_id = data[2]

      format = case flags
               when NOT_SEARCHABLE
                 "not_searchable"
               when SEARCHABLE
                 "searchable"
               when LOWERCASE_SEARCHABLE
                 "lowercase_searchable"
               else
                 "unknown"
               end

      searchable = flags == SEARCHABLE || flags == LOWERCASE_SEARCHABLE

      plaintext = decrypt_bytes(data, key)

      {
        plaintext:  plaintext,
        flags:      flags,
        key_id:     key_id,
        searchable: searchable,
        format:     format,
      }
    end

    # Check if data appears to be in Sequel column encryption format
    #
    # This performs basic validation without attempting decryption
    def self.valid_format?(data_base64 : String) : Bool
      return false if data_base64.empty?

      begin
        data = decode_base64(data_base64)
        return false if data.size < 4

        flags = data[0]
        return false unless flags.in?(NOT_SEARCHABLE, SEARCHABLE, LOWERCASE_SEARCHABLE)

        case flags
        when NOT_SEARCHABLE
          data.size >= MIN_SIZE_NOT_SEARCHABLE
        when SEARCHABLE, LOWERCASE_SEARCHABLE
          data.size >= MIN_SIZE_SEARCHABLE
        else
          false
        end
      rescue
        false
      end
    end

    private def self.decode_base64(encoded : String) : Bytes
      Base64.decode(encoded.tr("-_", "+/"))
    end

    private def self.decrypt_bytes(data : Bytes, key : String | Bytes, remove_padding : Bool = true) : String
      key_bytes = key.is_a?(String) ? key.to_slice : key

      if data.size < 4
        raise DecryptionError.new("Encrypted data too small (minimum 4 bytes for header)")
      end

      flags = data[0]
      _version = data[1]
      _key_id = data[2]
      _reserved = data[3]

      offset = case flags
               when NOT_SEARCHABLE
                 if data.size < MIN_SIZE_NOT_SEARCHABLE
                   raise DecryptionError.new("Encrypted data too small for NOT_SEARCHABLE format (minimum #{MIN_SIZE_NOT_SEARCHABLE} bytes)")
                 end
                 4
               when SEARCHABLE, LOWERCASE_SEARCHABLE
                 if data.size < MIN_SIZE_SEARCHABLE
                   raise DecryptionError.new("Encrypted data too small for SEARCHABLE format (minimum #{MIN_SIZE_SEARCHABLE} bytes)")
                 end
                 36
               else
                 raise DecryptionError.new("Invalid encryption flags: #{flags}")
               end

      required_size = offset + KEY_PART_SIZE + IV_SIZE + TAG_SIZE
      if data.size < required_size
        raise DecryptionError.new("Encrypted data too small (need at least #{required_size} bytes)")
      end

      key_part = data[offset, KEY_PART_SIZE]
      cipher_iv = data[offset + KEY_PART_SIZE, IV_SIZE]
      auth_tag = data[offset + KEY_PART_SIZE + IV_SIZE, TAG_SIZE]
      ciphertext = data[offset + KEY_PART_SIZE + IV_SIZE + TAG_SIZE..]

      cipher_key = OpenSSL::HMAC.digest(:sha256, key_bytes, key_part)

      cipher = AesGcm::Cipher.new
      begin
        decrypted_bytes = cipher.decrypt(
          key: cipher_key,
          ciphertext: ciphertext,
          iv: cipher_iv,
          auth_tag: auth_tag
        )
      rescue ex : OpenSSL::Cipher::Error
        raise DecryptionError.new("Decryption failed: #{ex.message} (check encryption key)")
      end

      if remove_padding
        if decrypted_bytes.size < 1
          raise DecryptionError.new("Decrypted data too small to contain padding information")
        end

        padding_length = decrypted_bytes[0].to_i
        if padding_length + 1 > decrypted_bytes.size
          raise DecryptionError.new("Invalid padding length: #{padding_length}")
        end

        String.new(decrypted_bytes[padding_length + 1..])
      else
        String.new(decrypted_bytes)
      end
    end
  end
end
