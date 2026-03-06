require "sequel"
require "json"

KEY = "24cd14f11f67153c9102df8d58e94b26"

DB = Sequel.sqlite
DB.create_table(:items) do
  primary_key :id
  String :secret
end

Sequel::Model.plugin :column_encryption do |enc|
  enc.key 0, KEY
end

class Item < Sequel::Model(DB[:items])
  plugin :column_encryption do |enc|
    enc.column :secret
  end
end

test_values = [
  "Hello, World!",
  "John Doe",
  "A" * 100,
  "x",
  "Special chars: \xC3\xA0\xC3\xA9\xC3\xAE\xC3\xB5\xC3\xBC".force_encoding("UTF-8"),
]

results = test_values.map do |value|
  item = Item.create(secret: value)
  raw = DB[:items].where(id: item.id).get(:secret)
  {plaintext: value, encrypted: raw}
end

puts JSON.generate(results)
