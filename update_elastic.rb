#!/usr/bin/env ruby
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require './tlsciphersuites.rb'

client = Elasticsearch::Client.new log: false

loop do

#data = client.search index: 'tlshandshakes', body: { size: 50, query: { bool: { must_not: { exists: { field: "tlsserverhello.cipherdata.auth" } } } } }
data = client.search index: 'tlshandshakes', body: { size: 50, query: { bool: { must_not: { exists: { field: "tlsclienthello.cipherdata.humanreadable" } } } } }

puts data["hits"]["hits"].length

break if data["hits"]["hits"].length == 0

data["hits"]["hits"].each do |hit|
  body = hit["_source"]

  cipher = TLSCipherSuite.new(body["tlsclienthello"]["ciphersuites"])

  body["tlsclienthello"]["cipherdata"] ||= {}
  body["tlsclienthello"]["cipherdata"]["humanreadable"] = cipher.humanreadable
  body["tlsclienthello"]["cipherdata"]["cipherset"]  = cipher.cipherset
  #body["tlsclienthello"]["cipherdata"]["pfs_avail"] = cipher.pfs_avail?
  #body["tlsclienthello"]["cipherdata"]["only_pfs"]  = cipher.only_pfs?
  #body["tlsclienthello"]["cipherdata"]["anull"]     = cipher.anull_present?
  #body["tlsclienthello"]["cipherdata"]["enull"]     = cipher.enull_present?
  #body["tlsclienthello"]["cipherdata"]["rc4"]       = cipher.rc4_present?
  #body["tlsclienthello"]["cipherdata"]["tripledes"] = cipher.tripledes_present?
  #body["tlsclienthello"]["cipherdata"]["des"]       = cipher.des_present?

#  cipher = TLSCipherSuite.by_hexstr(body["tlsserverhello"]["cipher"])

#  body["tlsserverhello"]["cipherdata"] ||= {}
#  body["tlsserverhello"]["cipherdata"]["FS"] = cipher[:pfs]
#  body["tlsserverhello"]["cipherdata"]["auth"] = cipher[:auth]
#  body["tlsserverhello"]["cipherdata"]["encry"] = cipher[:encryption]
#  body["tlsserverhello"]["cipherdata"]["keyx"] = cipher[:keyxchange]
#  body["tlsserverhello"]["cipherdata"]["name"] = cipher[:name]

  client.index index: hit["_index"], type: hit["_type"], id: hit["_id"], body: hit["_source"]
end

end
