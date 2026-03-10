require "openssl/hmac"
require "base64"

module AesGcm
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
