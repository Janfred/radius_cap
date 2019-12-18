#!/usr/bin/env ruby
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require './tlsciphersuites.rb'

client = Elasticsearch::Client.new log: false

data = client.search terminate_after: 50, index: 'tlshandshakes', body: { query: { bool: { must_not: { exists: { field: "tlsserverhello.cipherdata.FS" } } } } }

data["hits"]["hits"].each do |hit|
  body = hit["_source"]

  cipher = TLSCipherSuite.by_hexstr(body["tlsserverhello"]["cipher"])

  body["tlsserverhello"]["cipherdata"] = {}
  body["tlsserverhello"]["cipherdata"]["FS"] = cipher[:pfs]

  client.index index: hit["_index"], type: hit["_type"], id: hit["_id"], body: hit["_source"]
end
