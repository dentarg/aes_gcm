require "spec"
require "../src/aes_gcm"

describe AesGcm::SequelColumnEncryption do
  # Test data from the original Ruby script
  key = "24cd14f11f67153c9102df8d58e94b26"
  encrypted_data = "AAAAAM4LImpqpydSaTW4xW8P9EbeUA36hfElspicYl1HFDFM2sQATqr78uijno5RwJiTITMppEkpkbN_alpFOQOi77QgaJViniquDav9fibs"
  expected_plaintext = "John Doe"

  describe ".decrypt" do
    it "decrypts Sequel column encryption format correctly" do
      result = AesGcm::SequelColumnEncryption.decrypt(encrypted_data, key)
      result.should eq(expected_plaintext)
    end

    it "works with Bytes key" do
      key_bytes = key.to_slice
      result = AesGcm::SequelColumnEncryption.decrypt(encrypted_data, key_bytes)
      result.should eq(expected_plaintext)
    end

    it "raises error with wrong key" do
      wrong_key = "00000000000000000000000000000000"

      expect_raises(AesGcm::SequelColumnEncryption::DecryptionError, /Decryption failed/) do
        AesGcm::SequelColumnEncryption.decrypt(encrypted_data, wrong_key)
      end
    end

    it "raises error with invalid base64" do
      expect_raises(AesGcm::SequelColumnEncryption::DecryptionError, /Invalid base64/) do
        AesGcm::SequelColumnEncryption.decrypt("not valid base64!!!", key)
      end
    end

    it "raises error with data too small" do
      small_data = Base64.strict_encode("ab")

      expect_raises(AesGcm::SequelColumnEncryption::DecryptionError, /too small/) do
        AesGcm::SequelColumnEncryption.decrypt(small_data, key)
      end
    end

    it "raises error with invalid flags" do
      # Create data with invalid flags byte
      invalid_data = Bytes.new(100, 0_u8)
      invalid_data[0] = 99_u8 # Invalid flags
      encoded = Base64.strict_encode(invalid_data)

      expect_raises(AesGcm::SequelColumnEncryption::DecryptionError, /Invalid encryption flags/) do
        AesGcm::SequelColumnEncryption.decrypt(encoded, key)
      end
    end

    it "can decrypt without removing padding" do
      result = AesGcm::SequelColumnEncryption.decrypt(encrypted_data, key, remove_padding: false)
      # With padding included, it should start with padding byte
      result.size.should be > expected_plaintext.size
    end
  end

  describe ".decrypt_with_info" do
    it "returns decrypted data with metadata" do
      info = AesGcm::SequelColumnEncryption.decrypt_with_info(encrypted_data, key)

      info[:plaintext].should eq(expected_plaintext)
      info[:flags].should eq(0_u8)
      info[:key_id].should eq(0_u8)
      info[:searchable].should be_false
      info[:format].should eq("not_searchable")
    end

    # Searchable format decryption is tested end-to-end in ci/sequel_compat/
    # using actual Ruby Sequel-encrypted data (all three format variants).
  end

  describe ".valid_format?" do
    it "returns true for valid Sequel encrypted data" do
      AesGcm::SequelColumnEncryption.valid_format?(encrypted_data).should be_true
    end

    it "returns false for empty string" do
      AesGcm::SequelColumnEncryption.valid_format?("").should be_false
    end

    it "returns false for invalid base64" do
      AesGcm::SequelColumnEncryption.valid_format?("not base64!!!").should be_false
    end

    it "returns false for data too small" do
      small_data = Base64.strict_encode("abc")
      AesGcm::SequelColumnEncryption.valid_format?(small_data).should be_false
    end

    it "returns false for invalid flags" do
      invalid_data = Bytes.new(100, 0_u8)
      invalid_data[0] = 99_u8 # Invalid flags
      encoded = Base64.strict_encode(invalid_data)

      AesGcm::SequelColumnEncryption.valid_format?(encoded).should be_false
    end

    it "returns true for NOT_SEARCHABLE format" do
      # Create valid size data with NOT_SEARCHABLE flag
      data = Bytes.new(65, 0_u8)
      data[0] = 0_u8 # NOT_SEARCHABLE
      encoded = Base64.strict_encode(data)

      AesGcm::SequelColumnEncryption.valid_format?(encoded).should be_true
    end

    it "returns true for SEARCHABLE format" do
      # Create valid size data with SEARCHABLE flag
      data = Bytes.new(97, 0_u8)
      data[0] = 1_u8 # SEARCHABLE
      encoded = Base64.strict_encode(data)

      AesGcm::SequelColumnEncryption.valid_format?(encoded).should be_true
    end

    it "returns true for LOWERCASE_SEARCHABLE format" do
      # Create valid size data with LOWERCASE_SEARCHABLE flag
      data = Bytes.new(97, 0_u8)
      data[0] = 2_u8 # LOWERCASE_SEARCHABLE
      encoded = Base64.strict_encode(data)

      AesGcm::SequelColumnEncryption.valid_format?(encoded).should be_true
    end
  end

  describe "integration with original Ruby script" do
    it "produces identical results to Ruby sequel-column-encryption" do
      # This is the actual data from the Ruby script
      result = AesGcm::SequelColumnEncryption.decrypt(encrypted_data, key)

      result.should eq("John Doe")
    end
  end
end
