#!/usr/bin/env ruby

Dir.chdir '..'
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require './src/tlsciphersuites'

client = Elasticsearch::Client.new log: false

body_size = 1000
max_offset = 5000
total = 0
cur_offset = 0
cur_step = 1000


loop do

  bulk_data = []

  data = client.search index: 'tlshandshakes', body: {
    size: body_size,
    from: cur_offset,
    query: {
      bool: {
        must_not: [
          exists: {
            field: 'tls.tlsclienthello.cipherdata.all_mac'
          }
        ],
        must: [
          exists: {
            field: 'tls.tlsclienthello.ciphersuites.keyword'
          }
        ]
      }
    }
  }
  hits = data["hits"]["hits"]

  break if hits.length == 0 && cur_offset == 0

  total += hits.length

  puts "#{hits.length} - #{total}  --offs #{cur_offset}"

  hits.each do |hit|
    id = hit["_id"]
    body = hit["_source"]

    body["meta"]["scheme_ver"] = 3
    body["meta"].delete("exported")

    cipher = TLSCipherSuite.new(body["tls"]["tlsclienthello"]["ciphersuites"])

    body["tls"]["tlsclienthello"]["cipherdata"]["all_mac"] = cipher.all_mac
    body["tls"]["tlsclienthello"]["cipherdata"]["all_mac_list"] = cipher.all_mac.sort.join(' ')
    body["tls"]["tlsclienthello"]["cipherdata"]["cipherset_length"] = cipher.set_length
    body["tls"]["tlsclienthello"]["cipherdata"]["cipherset_length_noscsv"] = cipher.set_length_noscsv


    bulk_data << {id: id, data: body}
  end

  unless bulk_data.empty?
    client.bulk index: 'tlshandshakes', body: bulk_data.map{|x| {index: {_id: x[:id], data: x[:data]}}}
  end

  cur_offset += cur_step
  cur_offset = 0 if cur_offset > max_offset
end
