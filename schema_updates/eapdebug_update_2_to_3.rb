#!/usr/bin/env ruby
# frozen_string_literal: true

Dir.chdir '..'
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require_relative '../localconfig'

client = Elasticsearch::Client.new log: false, user: @config[:elastic_username], password: @config[:elastic_password]

body_size = 1000
max_offset = 5000
total = 0
cur_offset = 0
cur_step = 1000

loop do
  bulk_data = []

  data = client.search index: 'eapdebug', body: {
    size: body_size,
    from: cur_offset,
    query: {
      range: {
        'meta.scheme_ver': {
          gte: 2,
          lt: 3
        }
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

    body['meta']['scheme_ver'] = 3

    if body['radius']['attributes']['1'] && body['radius']['attributes']['1'].length == 1
      body['eap']['username_length'] = body['radius']['attributes']['1'][0].length / 2
    end

    bulk_data << { id: id, data: body }
  end

  unless bulk_data.empty?
    client.bulk index: 'eapdebug', body: bulk_data.map { |x| { index: { _id: x[:id], data: x[:data] } } }
  end

  cur_offset += cur_step
  cur_offset = 0 if cur_offset > max_offset
end
