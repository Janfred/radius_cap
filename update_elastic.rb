#!/usr/bin/env ruby
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require 'digest'
require './src/tlsciphersuites.rb'
require './src/macvendor.rb'


MacVendor.init_data

client = Elasticsearch::Client.new log: false

loop do

#data = client.search index: 'tlshandshakes', body: { size: 50, query: { bool: { must_not: { exists: { field: "tlsserverhello.cipherdata.auth" } } } } }
#data = client.search index: 'tlshandshakes', body: { size: 50, query: { bool: { must_not: { exists: { field: "tlsclienthello.cipherdata.humanreadable" } } } } }
data = client.search index: 'tlshandshakes', body: { size: 50, query: { bool: { must_not: { exists: { field: "vendor" } } } } }

puts data["hits"]["hits"].length

break if data["hits"]["hits"].length == 0

data["hits"]["hits"].each do |hit|
  body = hit["_source"]

  body["scheme_ver"] = 2

  body["vendor"] = MacVendor.by_oid(body["oui"])

#  body["tlsclienthello"]["cipherdata"]["supported_group_set"] = body["tlsclienthello"]["supportedgroups"].join('+')
#  body["tlsclienthello"]["cipherdata"]["signature_algorithm_set"] = body["tlsclienthello"]["signaturealgorithms"].join('+')
#  body["tlsclienthello"]["fingerprinting"] ||= {}
#  body["tlsclienthello"]["fingerprinting"]["v1"] = Digest::SHA2.hexdigest(
#    body["tlsclienthello"]["version"] + "|" +
#    body["tlsclienthello"]["cipherdata"]["cipherset"] + "|" +
#    body["tlsclienthello"]["cipherdata"]["supported_group_set"] + "|" +
#    body["tlsclienthello"]["cipherdata"]["signature_algorithm_set"] + "|" +
#    ((body["tlsclienthello"]["statusrequest"].nil? || body["tlsclienthello"]["statusrequest"] == []) ? "False" : body["tlsclienthello"]["statusrequest"]) + "|" +
#    (body["tlsclienthello"]["renegotiation"] ? "True" : "False") + "|" +
#    (body["tlsclienthello"]["extendedmastersecret"] ? "True" : "False") )

  #cipher = TLSCipherSuite.new(body["tlsclienthello"]["ciphersuites"])

  #body["tlsclienthello"]["cipherdata"] ||= {}
  #body["tlsclienthello"]["cipherdata"]["humanreadable"] = cipher.humanreadable
  #body["tlsclienthello"]["cipherdata"]["cipherset"]  = cipher.cipherset
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
