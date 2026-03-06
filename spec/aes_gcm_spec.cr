require "spec"
require "../src/aes_gcm"

describe AesGcm::Cipher do
  describe "#encrypt and #decrypt" do
    it "encrypts and decrypts data correctly" do
      cipher = AesGcm::Cipher.new
      key = "12345678901234567890123456789012"
      plaintext = "Hello, World!"

      encrypted = cipher.encrypt(key: key, plaintext: plaintext)
      decrypted = cipher.decrypt(encrypted)

      String.new(decrypted).should eq(plaintext)
    end

    it "works with binary data" do
      cipher = AesGcm::Cipher.new
      key = Bytes[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]
      plaintext = Bytes[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

      encrypted = cipher.encrypt(key: key, plaintext: plaintext)
      decrypted = cipher.decrypt(encrypted)

      decrypted.should eq(plaintext)
    end

    it "fails with wrong key" do
      cipher = AesGcm::Cipher.new
      key = "12345678901234567890123456789012"
      wrong_key = "00000000000000000000000000000000"
      plaintext = "secret"

      encrypted = cipher.encrypt(key: key, plaintext: plaintext)

      expect_raises(OpenSSL::Cipher::Error, /authentication verification failed/) do
        cipher.decrypt(
          key: wrong_key,
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          auth_tag: encrypted.auth_tag
        )
      end
    end

    it "fails with tampered ciphertext" do
      cipher = AesGcm::Cipher.new
      key = "12345678901234567890123456789012"
      plaintext = "secret"

      encrypted = cipher.encrypt(key: key, plaintext: plaintext)

      # Tamper with ciphertext
      tampered = encrypted.ciphertext.dup
      tampered[0] = tampered[0] ^ 0xFF

      expect_raises(OpenSSL::Cipher::Error, /authentication verification failed/) do
        cipher.decrypt(
          key: key,
          ciphertext: tampered,
          iv: encrypted.iv,
          auth_tag: encrypted.auth_tag
        )
      end
    end

    it "fails with wrong auth tag" do
      cipher = AesGcm::Cipher.new
      key = "12345678901234567890123456789012"
      plaintext = "secret"

      encrypted = cipher.encrypt(key: key, plaintext: plaintext)

      # Use wrong auth tag
      wrong_tag = Bytes.new(16, 0_u8)

      expect_raises(OpenSSL::Cipher::Error, /authentication verification failed/) do
        cipher.decrypt(
          key: key,
          ciphertext: encrypted.ciphertext,
          iv: encrypted.iv,
          auth_tag: wrong_tag
        )
      end
    end

    it "validates key size" do
      cipher = AesGcm::Cipher.new
      short_key = "short"

      expect_raises(ArgumentError, /Key must be 32 bytes/) do
        cipher.encrypt(key: short_key, plaintext: "data")
      end
    end

    it "generates random IVs by default" do
      cipher = AesGcm::Cipher.new
      key = "12345678901234567890123456789012"
      plaintext = "test"

      encrypted1 = cipher.encrypt(key: key, plaintext: plaintext)
      encrypted2 = cipher.encrypt(key: key, plaintext: plaintext)

      encrypted1.iv.should_not eq(encrypted2.iv)
      encrypted1.ciphertext.should_not eq(encrypted2.ciphertext)
    end

    it "allows custom IV" do
      cipher = AesGcm::Cipher.new
      key = "12345678901234567890123456789012"
      custom_iv = Bytes[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
      plaintext = "test"

      encrypted = cipher.encrypt(key: key, plaintext: plaintext, iv: custom_iv)

      encrypted.iv.should eq(custom_iv)

      decrypted = cipher.decrypt(encrypted)
      String.new(decrypted).should eq(plaintext)
    end
  end

  describe "#encrypt_base64 and #decrypt_base64" do
    it "encrypts to base64 and decrypts correctly" do
      cipher = AesGcm::Cipher.new
      key = "12345678901234567890123456789012"
      plaintext = "Hello, Base64!"

      encoded = cipher.encrypt_base64(key: key, plaintext: plaintext)
      decoded = cipher.decrypt_base64(encoded: encoded, key: key)

      String.new(decoded).should eq(plaintext)
    end

    it "produces URL-safe base64" do
      cipher = AesGcm::Cipher.new
      key = "12345678901234567890123456789012"
      plaintext = "test"

      encoded = cipher.encrypt_base64(key: key, plaintext: plaintext)

      # URL-safe base64 should not contain + or /
      encoded.should_not contain("+")
      encoded.should_not contain("/")
    end
  end

  describe AesGcm::EncryptedData do
    describe "#to_base64 and .from_base64" do
      it "round-trips correctly" do
        cipher = AesGcm::Cipher.new
        key = "12345678901234567890123456789012"
        plaintext = "test data"

        encrypted = cipher.encrypt(key: key, plaintext: plaintext)
        encoded = encrypted.to_base64

        decoded = AesGcm::EncryptedData.from_base64(encoded, key)

        decoded.iv.should eq(encrypted.iv)
        decoded.auth_tag.should eq(encrypted.auth_tag)
        decoded.ciphertext.should eq(encrypted.ciphertext)
      end
    end
  end
end
