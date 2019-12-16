require 'elasticsearch'
require 'digest'

class ElasticHelper
  @@elasticdata = []
  @@waitcond = nil
  @@client

  def self.initialize_elasticdata
    @@elasticdata = []
    @@elasticdata.extend(MonitorMixin)
    @@waitcond = @@elasticdata.new_cond
  end

  def self.elasticdata
    @@elasticdata
  end

  def self.waitcond
    @@waitcond
  end

  def self.client
    @@client
  end

  def self.client=(val)
    @@client = val
  end
end

ElasticHelper.client = Elasticsearch::Client.new log: false

def convert_data_to_elasticsearch(data)
  to_insert = {id: nil, data: {}}
  to_insert[:data][:realm] = data[:username].split("@")[1]
  to_insert[:data][:oui] = data[:mac].split(":")[0,3].join(":")
  to_insert[:data][:eapmethod] = data[:eapmethod]
  to_insert[:data][:tlsclienthello] = data[:tlsclienthello]
  to_insert[:data][:tlsserverhello] = data[:tlsserverhello]
  to_insert[:id] = Digest::SHA2.hexdigest "#{data[:username]}#{data[:mac]}"
  to_insert
end

def insert_into_elastic(raw_data)
  to_ins = convert_data_to_elasticsearch(raw_data)
  ElasticHelper.client.index index: 'tlshandshakes', type: 'tlshandshake', id: to_ins[:id], body: to_ins[:data]
end
