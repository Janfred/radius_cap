#!/usr/bin/env ruby
# frozen_string_literal: true

Dir.chdir '..'
require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'

client = Elasticsearch::Client.new log: false

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

    body['meta']['scheme_ver'] = 4

    if body['eap']['matches_username_length']
      eapmsg = body['eap']['rawmsg']
      radmsg = body['radius']['attributes']['1'][0]

      total_bytes = radmsg.length / 2

      (0..(total_bytes - 1)).reverse_each do |i|
        next if eapmsg[i * 2 + 10, 2] == radmsg[i * 2, 2]

        body['eap']['number_of_equal_bytes'] = (total_bytes - 1) - i

        if data['eap']['number_of_equal_bytes'].zero?
          body['eap'].delete 'index_of_first_equal'
        else
          body['eap']['index_of_first_equal'] = i
        end
        break
      end
    end

    bulk_data << { id: id, data: body }
  end

  unless bulk_data.empty?
    client.bulk index: 'eapdebug', body: bulk_data.map { |x| { index: { _id: x[:id], data: x[:data] } } }
  end

  cur_offset += cur_step
  cur_offset = 0 if cur_offset > max_offset
end
