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

  # Get Username and MAC-Address and remove it from the data
  username = ""
  if data[:radius] && data[:radius][:attributes] && data[:radius][:attributes][:username]
    username = data[:radius][:attributes][:username]
    data[:radius][:attributes].delete :username
  end
  if data[:eap] && data[:eap][:information] && data[:eap][:information][:eap_identity]
    username ||= data[:eap][:information][:eap_identity]
    data[:eap][:information].delete :eap_identity
  end

  realm = username.split('@')[1]

  mac = 'ff:ff:ff:ff:ff:ff'
  if data[:radius] && data[:radius][:attributes] && data[:radius][:attributes][:mac]
    mac = data[:radius][:attributes][:mac]
    data[:radius][:attributes].delete :mac
  end
  meta = {}
  meta[:last_seen] = Time.now.utc.iso8601
  meta[:scheme_ver] = 0 # TODO
  meta[:caputre_ver] = 0 # TODO
  meta[:realm] = realm
  meta[:oui] = mac.split(':')[0,3].join ':'
  meta[:vendor] = MacVendor.by_oid(meta[:oui])

  data[:meta] = meta

  to_insert = {id: nil, data: data}
  to_insert[:id] = Digest::SHA2.hexdigest "#{data[:username]}#{data[:mac]}"
  to_insert
end

# Inserts data into Elasticsearch
# @param raw_data [Hash] Hash with data to insert.
# @param debug [Boolean] If set to true the data will be printed on stdout. Defaults to false.
# @param no_direct_elastic [Boolean] If set to true, the data will not be written in elastic. Defaults to false.
# @param output_to_file [Boolean] If set to true, the data will be written in a File named <id>.json. Defaults to false.
# @return nil
def insert_into_elastic(raw_data, debug=false, no_direct_elastic=false, output_to_file=false)
  to_ins = convert_data_to_elasticsearch(raw_data)
  ElasticHelper.client.index index: 'tlshandshakes', type: 'tlshandshake', id: to_ins[:id], body: to_ins[:data] unless no_direct_elastic
  puts to_ins if debug
  File.write(File.join('data', to_ins[:id]),to_ins[:data].to_s) if output_to_file
  nil
end
