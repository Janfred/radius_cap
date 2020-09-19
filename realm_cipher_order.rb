#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'

client = Elasticsearch::Client.new log: false

realm_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { realms: { terms: { field: "meta.realm.keyword", size: 100000 } } } }

realm_data["aggregations"]["realms"]["buckets"].each do |realm_bucket|
  cur_realm = realm_bucket["key"]
  puts "Checking #{cur_realm}"

  realm_match = { match_phrase: { "meta.realm.keyword": cur_realm } }
  realm_query = { bool: { filter: realm_match } }

  chosen_ciphers = []

  cipher_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { cipher: { terms: { field: "tls.tlsserverhello.cipher.keyword", size: 1000 } } }, query: realm_query }
  cipher_data["aggregations"]["cipher"]["buckets"].each do |cipher_bucket|
    chosen_ciphers << cipher_bucket["key"]
  end

  client_preference = false
  server_preference = false
  preference_list = []

  ciphersets = []
  cipherset_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { cipherset: { terms: { field: "tls.tlsclienthello.cipherdata.cipherset.keyword" } } }, query: realm_query }
  cipherset_data["aggregations"]["cipherset"]["buckets"].each do |cipherset_bucket|
    ciphersets << cipherset_bucket["key"]
  end

  chosen_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { chosen: { composite: { sources: [ { cipherset: { terms: { field: "tls.tlsclienthello.cipherdata.cipherset.keyword" } } }, { cipher: { terms: { field: "tls.tlsserverhello.cipher.keyword" } } } ] } } }, query: realm_query }
  chosen_data["aggregations"]["chosen"]["buckets"].each do |chosen_bucket|
    ciphersuite = chosen_bucket["key"]["cipherset"].split(' ')
    chosen = chosen_bucken["key"]["cipher"]

    chosen_index = ciphersuite.index chosen

    chosen_ciphers.each do |cs|
      next if chosen == cs
      cur_ind = ciphersuite.index cs
      next if cur_ind.nil?
      if chosen_index < cur_ind
        # Possible Client Preference
        client_preference = true
      end
      if chosen_index > cur_ind
        # Possible Server Preference
        server_preference = true
      end
    end
  end

  puts " Client Preference: #{ client_preference }"
  puts " Server Preference: #{ server_preference }"
end
