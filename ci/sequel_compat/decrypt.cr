require "json"
require "../../src/aes_gcm"

key = "24cd14f11f67153c9102df8d58e94b26"

input = STDIN.gets_to_end
data = JSON.parse(input)

failures = 0

data.as_a.each do |entry|
  plaintext = entry["plaintext"].as_s
  encrypted = entry["encrypted"].as_s

  begin
    result = AesGcm::SequelColumnEncryption.decrypt(encrypted, key)
    if result == plaintext
      puts "at=info msg=pass plaintext=#{plaintext.inspect}"
    else
      puts "at=error msg=mismatch expected=#{plaintext.inspect} got=#{result.inspect}"
      failures += 1
    end
  rescue ex
    puts "at=error msg=decrypt_failed plaintext=#{plaintext.inspect} error=#{ex.message}"
    failures += 1
  end
end

if failures > 0
  STDERR.puts "at=error msg=\"#{failures} test(s) failed\""
  exit 1
else
  puts "at=info msg=\"all #{data.as_a.size} tests passed\""
end
