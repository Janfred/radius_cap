#!/usr/bin/env ruby
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require './src/fingerprint'

client = Elasticsearch::Client.new log: false

Fingerprint.check_new_file

fp_db = Fingerprint.get_fp_db

fp_db.each do |fp, fp_data|
  puts "Update all fingerprints #{fp}"
  loop do
    data = client.search index: 'tlshandshakes', body: {
        size: 150,
        query: {
            bool: {
                filter: [
                    {
                        match_phrase: {
                            "tls.tlsclienthello.fingerprinting.v2.keyword": fp
                        }
                    },
                    {
                        match_phrase: {
                            "tls.tlsclienthello.fingerprinting.osdetails.os.keyword": "Not in FP-DB"
                        }
                    }
                ]
            }
        }
    }

    length = data["hits"]["hits"].length
    break if length==0
    puts "  #{length}"

    data["hits"]["hits"].each do |hit|
      body = hit["_source"]
      body["tls"]["tlsclienthello"]["fingerprinting"]["osdetails"] = Fingerprint.to_h fp
      client.index index: hit["_index"], type: hit["_type"], id: hit["_id"], body: body
    end
  end
end