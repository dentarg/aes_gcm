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

class NotSearchableItem < Sequel::Model(DB[:items])
  plugin :column_encryption do |enc|
    enc.column :secret
  end
end

class SearchableItem < Sequel::Model(DB[:items])
  plugin :column_encryption do |enc|
    enc.column :secret, searchable: true
  end
end

class LowercaseSearchableItem < Sequel::Model(DB[:items])
  plugin :column_encryption do |enc|
    enc.column :secret, searchable: :case_insensitive
  end
end

test_values = [
  "Hello, World!",
  "John Doe",
  "A" * 100,
  "x",
  "Special chars: \xC3\xA0\xC3\xA9\xC3\xAE\xC3\xB5\xC3\xBC".force_encoding("UTF-8"),
]

results = []

test_values.each do |value|
  item = NotSearchableItem.create(secret: value)
  raw = DB[:items].where(id: item.id).get(:secret)
  results << {plaintext: value, encrypted: raw, format: "not_searchable"}

  item = SearchableItem.create(secret: value)
  raw = DB[:items].where(id: item.id).get(:secret)
  results << {plaintext: value, encrypted: raw, format: "searchable"}

  item = LowercaseSearchableItem.create(secret: value)
  raw = DB[:items].where(id: item.id).get(:secret)
  results << {plaintext: value, encrypted: raw, format: "lowercase_searchable"}
end

puts JSON.generate(results)
