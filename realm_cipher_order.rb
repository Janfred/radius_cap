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

  if chosen_ciphers.length < 2
    puts " No Preference analysis possible, just one ciphersuite"
    next
  end


  ciphersets = []
  cipherset_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { cipherset: { terms: { field: "tls.tlsclienthello.cipherdata.cipherset.keyword", size: 1000 } } }, query: realm_query }
  cipherset_data["aggregations"]["cipherset"]["buckets"].each do |cipherset_bucket|
    ciphersets << cipherset_bucket["key"]
  end

  cipher_orders = []
  client_preference = false
  no_client_preference = false
  preference_checkable = false

  chosen_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { chosen: { size: 1000, composite: { sources: [ { cipherset: { terms: { field: "tls.tlsclienthello.cipherdata.cipherset.keyword" } } }, { cipher: { terms: { field: "tls.tlsserverhello.cipher.keyword" } } } ] } } }, query: realm_query }
  chosen_data["aggregations"]["chosen"]["buckets"].each do |chosen_bucket|
    ciphersuite = chosen_bucket["key"]["cipherset"].split(' ')
    chosen = chosen_bucket["key"]["cipher"]

    puts "  " + ciphersuite.join(' ')
    puts "  " + chosen
    puts ""

    chosen_index = ciphersuite.index chosen

    chosen_ciphers.each do |cs|
      next if chosen == cs


      cur_ind = ciphersuite.index cs
      next if cur_ind.nil?

      cipher_orders << [chosen, cs]
      preference_checkable = true

      if chosen_index < cur_ind
        # Possible Client Preference
        client_preference = true
      end
      if chosen_index > cur_ind
        # No Client preference
        no_client_preference = true
      end
    end
  end

  unless preference_checkable
    puts " Preference not checkable."
    next
  end

  server_preference = true
  cipher_orders.uniq!
  puts " Cipher Orders: #{cipher_orders}"
  cipher_orders.each do |entry|
    if cipher_orders.include? [entry[1],entry[0]]
      server_preference = false
      break
    end
  end

  client_preference = client_preference & !no_client_preference

  puts " Client Preference: #{ client_preference }"
  puts " Server Preference: #{ server_preference }"
end
