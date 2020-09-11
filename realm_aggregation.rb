#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'

client = Elasticsearch::Client.new log: false

realm_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { realms: { terms: { field: "meta.realm.keyword", size: 100000 } } } }

realm_data["aggregations"]["realms"]["buckets"].each do |realm_bucket|
  cur_realm = realm_bucket["key"]
  puts "Aggregating for realm #{cur_realm}"

  realm_body = {}
  realm_body[:realm] = cur_realm
  realm_body[:tld] = cur_realm.split(".").last
  realm_body[:clients] = realm_bucket["doc_count"]

  realmmatch = {match_phrase: { "meta.realm.keyword": cur_realm } }
  realm_query = { bool: { filter: { match_phrase: { "meta.realm.keyword": cur_realm } } } }

  eap_tls = client.search index: 'tlshandshakes', body: { size: 10, query: { bool: { filter: [ realmmatch ], must: { exists: { field: "tls.tlsclienthello.version" }  } } } }
  if eap_tls["hits"]["hits"].length == 0
    puts "  NO EAP DATA. SKIPPING"
    next
  end

  puts "  TLS Versions"
  realm_body[:tls_version] = {}
  realm_body[:tls_version][:all] = []
  realm_body[:tls_version][:seperate] = {"TLSv1.0": false, "TLSv1.1": false, "TLSv1.2": false, "TLSv1.3": false}
  realm_body[:client_version] = {}
  realm_body[:client_version][:all] = []
  realm_body[:client_version][:seperate] = {"TLSv1.0": false, "TLSv1.1": false, "TLSv1.2": false, "TLSv1.3": false}

  version_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { version: { terms: { field: "tls.tlsserverhello.version.keyword", size: 100 } } }, query: realm_query }
  version_data["aggregations"]["version"]["buckets"].each do |version_bucket|
    realm_body[:tls_version][:all] << version_bucket["key"]
    realm_body[:tls_version][:seperate][version_bucket["key"].to_sym] = true
  end

  cl_vers_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { version: { terms: { field: "tls.tlsclienthello.version.keyword", size: 100 } } }, query: realm_query }
  cl_vers_data["aggregations"]["version"]["buckets"].each do |cl_vers_bucket|
    realm_body[:client_version][:all] << cl_vers_bucket["key"]
    realm_body[:client_version][:seperate][cl_vers_bucket["key"].to_sym] = true
  end

  puts "  Seen Key Exchange Algorithms"
  realm_body[:keyx] = {}
  realm_body[:keyx][:seperate] = {RSA: false, ECDHE: false, DHE: false }
  realm_body[:keyx][:all] = []
  keyx_data = client.search index: 'tlshandshakes', body: { size: 0, aggs: { keyx: { terms: { field: "tls.tlsserverhello.cipherdata.keyx.keyword", size: 100 } } }, query: realm_query }
  keyx_data["aggregations"]["keyx"]["buckets"].each do |keyx_bucket|
    realm_body[:keyx][:all] << keyx_bucket["key"]
    realm_body[:keyx][:seperate][keyx_bucket["key"].to_sym] = true
  end

  emsclientyes = { match_phrase: { "tls.tlsclienthello.extendedmastersecret": true } }
  emsclientno  = { match_phrase: { "tls.tlsclienthello.extendedmastersecret": false } }
  emsserveryes = { match_phrase: { "tls.tlsserverhello.extendedmastersecret": true } }
  emsserverno  = { match_phrase: { "tls.tlsserverhello.extendedmastersecret": false } }

  puts "  Extended Master Secret"
  ems_working     = client.search index: 'tlshandshakes', body: { size: 10, query: { bool: { filter: [ realmmatch, emsclientyes, emsserveryes ] } } }
  ems_not_working = client.search index: 'tlshandshakes', body: { size: 10, query: { bool: { filter: [ realmmatch, emsclientyes, emsserverno  ] } } }
  ems_unsure      = client.search index: 'tlshandshakes', body: { size: 10, query: { bool: { filter: [ realmmatch, emsclientno,  emsserverno  ] } } }
  ems_invalid     = client.search index: 'tlshandshakes', body: { size: 10, query: { bool: { filter: [ realmmatch, emsclientno,  emsserveryes ] } } }

  ems_working_bool     = ems_working["hits"]["hits"].length > 0
  ems_not_working_bool = ems_not_working["hits"]["hits"].length > 0
  ems_unsure_bool      = ems_unsure["hits"]["hits"].length > 0
  ems_invalid_bool     = ems_invalid["hits"]["hits"].length > 0

  if ems_invalid_bool
    # This should actually not happen.
    # Here the client did not include EMS, but the server answered with it.
    realm_body[:extended_master_secret] = "INVALID"
  elsif ems_not_working_bool && ems_working_bool
    realm_body[:extended_master_secret] = "Inconsistent"
  elsif ems_not_working_bool
    realm_body[:extended_master_secret] = "Not supported"
  elsif ems_working_bool
    realm_body[:extended_master_secret] = "Supported"
  elsif ems_unsure_bool
    realm_body[:extended_master_secret] = "Unsure"
  else
    realm_body[:extended_master_secret] = "NO DATA"
  end

  client.index index: 'realm_metadata', type: 'realm', id: cur_realm, body: realm_body
end