#!/usr/bin/env ruby
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require './tlsciphersuites.rb'

client = Elasticsearch::Client.new log: false

loop do

data = client.search index: 'tlshandshakes', body: { size: 50, query: { bool: { must_not: { exists: { field: "tlsserverhello.cipherdata.auth" } } } } }

puts data["hits"]["hits"].length

break if data["hits"]["hits"].length == 0

data["hits"]["hits"].each do |hit|
  body = hit["_source"]

  cipher = TLSCipherSuite.by_hexstr(body["tlsserverhello"]["cipher"])

  body["tlsserverhello"]["cipherdata"] ||= {}
  body["tlsserverhello"]["cipherdata"]["FS"] = cipher[:pfs]
  body["tlsserverhello"]["cipherdata"]["auth"] = cipher[:auth]
  body["tlsserverhello"]["cipherdata"]["encry"] = cipher[:encryption]
  body["tlsserverhello"]["cipherdata"]["keyx"] = cipher[:keyxchange]
  body["tlsserverhello"]["cipherdata"]["name"] = cipher[:name]

  client.index index: hit["_index"], type: hit["_type"], id: hit["_id"], body: hit["_source"]
end

end
