#!/usr/bin/env ruby
# frozen_string_literal: true

Dir.chdir '..'
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require_relative '../src/tlsciphersuites'
require_relative '../localconfig'

client = Elasticsearch::Client.new log: false, user: @config[:elastic_username], password: @config[:elastic_password]

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
            field: 'tls.tlsclienthello.cipherdata.min_sec_lvl'
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
  hits = data['hits']['hits']

  break if hits.empty? && cur_offset.zero?

  total += hits.length

  puts "#{hits.length} - #{total}  --offs #{cur_offset}"

  hits.each do |hit|
    id = hit['_id']
    body = hit['_source']

    body['meta']['scheme_ver'] = 2
    body['meta'].delete('exported')

    cipher = TLSCipherSuite.new(body['tls']['tlsclienthello']['ciphersuites'])

    body['tls']['tlsclienthello']['cipherdata']['export'] = cipher.includes_export?
    body['tls']['tlsclienthello']['cipherdata']['broken'] = cipher.includes_broken?
    body['tls']['tlsclienthello']['cipherdata']['outdated'] = cipher.includes_old_outdated?
    body['tls']['tlsclienthello']['cipherdata']['min_sec_lvl'] = cipher.min_sec_level
    body['tls']['tlsclienthello']['cipherdata']['max_sec_lvl'] = cipher.max_sec_level
    body['tls']['tlsclienthello']['cipherdata']['all_keyx'] = cipher.all_keyx
    body['tls']['tlsclienthello']['cipherdata']['all_auth'] = cipher.all_auth
    body['tls']['tlsclienthello']['cipherdata']['all_encr'] = cipher.all_encr
    body['tls']['tlsclienthello']['cipherdata']['all_keyx_list'] = cipher.all_keyx.sort.join(' ')
    body['tls']['tlsclienthello']['cipherdata']['all_auth_list'] = cipher.all_auth.sort.join(' ')
    body['tls']['tlsclienthello']['cipherdata']['all_encr_list'] = cipher.all_encr.sort.join(' ')


    bulk_data << { id: id, data: body }
  end

  unless bulk_data.empty?
    client.bulk index: 'tlshandshakes', body: bulk_data.map { |x| { index: { _id: x[:id], data: x[:data] } } }
  end

  cur_offset += cur_step
  cur_offset = 0 if cur_offset > max_offset
end
