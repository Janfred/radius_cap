require 'elasticsearch'
require 'singleton'
require 'digest'
require './macvendor.rb'

# Helper class for dealing with ElasticSearch
class ElasticHelper
  include Singleton

  attr_reader :priv_elasticdata
  attr_reader :priv_waitcond
  attr_reader :priv_client
  # Data to be inserted in ElasticSearch. Access to this variable must be synchronized.
  # @private
  @priv_elasticdata = []
  # Wait condition helper for synchronizing access to @@elasticdata
  # @private
  @priv_waitcond = nil
  # Client connection
  # @private
  @priv_client = nil

  # Initializes the Connection to Elasticsearch and loads MacVendor Database
  # @param debug [Boolean] If set to true the Client connection will not be established. Defaults to false.
  # @return nil
  def self.initialize_elasticdata(debug=false)
    self.instance.priv_initialize_elasticdata(debug)
  end

  # Private Helper Method for Elasticsearch initializer
  # @private
  # @param debug [Boolean] If set to true the Client connection will not be established. Defaults to false.
  # @return nil
  def priv_initialize_elasticdata(debug)
    @priv_elasticdata = []
    @priv_elasticdata.extend(MonitorMixin)
    @priv_waitcond = @priv_elasticdata.new_cond
    @priv_client = Elasticsearch::Client.new log: false unless debug
    MacVendor.init_data
    nil
  end

  # Get current elasticdata
  def self.elasticdata
    self.instance.priv_elasticdata
  end

  # Get Wait condition helper
  def self.waitcond
    self.instance.priv_waitcond
  end

  # Get the client connection
  def self.client
    self.instance.priv_client
  end

end


# Takes the given data and adds metadata for elasticsearch
# @param data [Hash] Data from TLS Handshake Parsing
# @return [Hash] Data in Elasticsearch format
def convert_data_to_elasticsearch(data)
  to_insert = {id: nil, data: {}}
  to_insert[:data][:last_seen] = Time.now.utc.iso8601
  to_insert[:data][:scheme_ver] = data[:scheme_ver]
  to_insert[:data][:capture_ver] = data[:capture_ver]
  to_insert[:data][:realm] = data[:username].split("@")[1]
  to_insert[:data][:oui] = data[:mac].split(":")[0,3].join(":")
  to_insert[:data][:vendor] = MacVendor.by_oid(to_insert[:data][:oui])
  to_insert[:data][:eapmethod] = data[:eapmethod]
  to_insert[:data][:tlsclienthello] = data[:tlsclienthello]
  to_insert[:data][:tlsserverhello] = data[:tlsserverhello]
  to_insert[:id] = Digest::SHA2.hexdigest "#{data[:username]}#{data[:mac]}"
  to_insert
end

# Inserts data into Elasticsearch
# @param raw_data [Hash] Hash with data to insert.
# @param debug [Boolean] If set to true the data will be printed instead of inserting it into Elasticsearch. Defaults to false.
# @return nil
def insert_into_elastic(raw_data, debug=false)
  to_ins = convert_data_to_elasticsearch(raw_data)
  ElasticHelper.client.index index: 'tlshandshakes', type: 'tlshandshake', id: to_ins[:id], body: to_ins[:data] unless debug
  puts to_ins if debug
  nil
end
