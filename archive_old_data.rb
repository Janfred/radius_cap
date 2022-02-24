#!/usr/bin/env ruby
# frozen_string_literal: true

require 'rubygems'
require 'bundler/setup'
require 'elasticsearch'
require 'digest'
require 'date'


require_relative './localconfig'

months = 3
now = DateTime.now
limit = now << months

limit_s = limit.strftime('%Y-%m-%dT%H:%M:%S.%LZ')


client = Elasticsearch::Client.new log: false,
                                   user: @config[:elastic_username],
                                   password: @config[:elastic_password]

@seen_ids = []

def random_id
  Digest::SHA2.hexdigest (('a'..'z').to_a * 50).sample(50).join('')
end

loop do
  data = client.search index: 'tlshandshakes', body: { size: 500, query: {
    bool: { filter: [{ range: {
      "meta.last_seen": {
        format: 'strict_date_optional_time',
        gte: '1970-01-01T00:00:00.000Z',
        lte: limit_s
      }
    } }] }
  } }

  puts data['hits']['hits'].length

  break if data['hits']['hits'].empty?

  delete_bulk = []
  insert_bulk = {}

  data['hits']['hits'].each do |hit|
    body = hit['_source']
    id = hit['_id']
    next if @seen_ids.include? id

    @seen_ids << id

    lastseen = body['meta']['last_seen']
    lastseen_d = DateTime.parse(lastseen)

    delete_bulk << { delete: { _id: id } }
    insert_bulk[lastseen_d.year] ||= []
    insert_bulk[lastseen_d.year] << { index: { _id: random_id, data: body } }
  end

  client.bulk index: 'tlshandshakes', body: delete_bulk
  insert_bulk.each_key do |year|
    client.bulk index: "tlshandshakes_archive_#{year}", body: insert_bulk[year]
  end
end
