# frozen_string_literal: true

require 'elasticsearch'
require 'singleton'
require 'digest'
require_relative './macvendor'

# Helper class for dealing with ElasticSearch
# @!attribute [r] priv_elasticdata
#   @return [Array] Data to be inserted in ElasticSearch.
#     Access to this variable must be synchronized.
#   @private
# @!attribute [r] priv_waitcond
#   @return [Object] Wait condition helper for synchronizing access to elasticdata
#   @private
# @!attribute [r] priv_client
#   @return [Object] Client connection to elasticsearch
#   @private
class ElasticHelper
  include Singleton
  include SemanticLogger::Loggable

  attr_reader :priv_elasticdata, :priv_waitcond, :priv_client

  def initialize
    @priv_known_ids = []
    @priv_bulk = nil
    @bulk_data_store = []
  end

  # Set Bulk insert size
  # @private
  # @param value [Integer,NilClass] Bulk size or nil for no bulk insertion
  def priv_bulk_insert=(value)
    @priv_bulk = value
  end

  # Get Bulk insert size
  # @private
  # @return [Integer,NilClass] Insertion bulk size or nil if bulk insertion not active
  def priv_bulk_insert
    @priv_bulk
  end

  # Set Bulk insert size
  # @param value [Integer,NilClass] Bulk size or nil for no bulk insertion
  def self.bulk_insert=(value)
    instance.priv_bulk_insert = value
  end

  # Get Bulk insert size
  # @return [Integer,NilClass] Insertion bulk size or nil if bulk insertion not active
  def self.bulk_insert
    instance.priv_bulk_insert
  end

  # Bulk data to insert
  # @private
  # @return [Array] Data to insert
  def priv_bulk_data
    @bulk_data_store
  end

  # Clear bulk data
  # @private
  def priv_clear_bulk_data
    @bulk_data_store = []
  end

  # Clear bulk data
  def self.clear_bulk_data
    instance.priv_clear_bulk_data
  end

  # Bulk data to insert
  # @return [Array] Data to insert
  def self.bulk_data
    instance.priv_bulk_data
  end

  # Initializes the Connection to Elasticsearch and loads MacVendor Database
  # @param debug [Boolean] If set to true the Client connection will not be established. Defaults to false.
  # @return nil
  def self.initialize_elasticdata(debug = false)
    instance.priv_initialize_elasticdata(debug)
  end

  # Private Helper Method for Elasticsearch initializer
  # @private
  # @param debug [Boolean] If set to true the Client connection will not be established. Defaults to false.
  # @return nil
  def priv_initialize_elasticdata(debug)
    @priv_elasticdata = []
    @priv_elasticdata.extend(MonitorMixin)
    @priv_waitcond = @priv_elasticdata.new_cond
    unless debug
      @priv_client = Elasticsearch::Client.new log: false,
                                               user: BlackBoard.config[:elastic_username],
                                               password: BlackBoard.config[:elastic_password]
    end
    MacVendor.init_data
    nil
  end

  # Check if a data with the given id already exists in Elasticsearch
  # @param elastic_id [String] id of the data item in waiting
  # @param check_online [Boolean] whether to check against elasticsearch or not.
  #   May be disabled if the Queue reaches a certain high watermark of pending records.
  # @return [Boolean] if the id already is taken by an item in Elasticsearch
  def self.check_exists(elastic_id, check_online = true)
    instance.priv_check_exists elastic_id, check_online
  end

  # Checks if elastic_id exists in Elasticsearch.
  # First it checks the locally saved ids, if the id is not found it looks up the ID in the Elastic database
  # @param elastic_id [String] ID of the elastic data
  # @param check_online [Boolean] whether to check against elasticsearch or not.
  #   May be disabled if the Queue reaches a certain high watermark of pending records.
  # @return [Boolean] if the elastic_id is already known.
  def priv_check_exists(elastic_id, check_online = true)
    return true if @priv_known_ids.include? elastic_id

    @priv_known_ids << elastic_id
    # This is for debugging purposes (if the elastic write is disabled)
    return false if @priv_client.nil?

    # Now we look up the id, but only if we are checking online
    if check_online
      data = @priv_client.search index: 'tlshandshakes', body: { query: { match: { "_id": elastic_id } } }
      # Return result of elasticsearch
      !data['hits']['hits'].empty?
    else
      false
    end
  end

  # Get current elasticdata
  def self.elasticdata
    instance.priv_elasticdata
  end

  # Get Wait condition helper
  def self.waitcond
    instance.priv_waitcond
  end

  # Get the client connection
  def self.client
    instance.priv_client
  end

  # Takes the given data and adds metadata for elasticsearch
  # @param data [Hash] Data from TLS Handshake Parsing
  # @return [Hash] Data in Elasticsearch format
  def self.convert_data_to_elasticsearch(data)

    # Get Username and MAC-Address and remove it from the data
    username = nil
    if data[:radius] && data[:radius][:attributes] && data[:radius][:attributes][:username]
      logger.trace "Username from RADIUS #{data[:radius][:attributes][:username]}"
      username = data[:radius][:attributes][:username]
      data[:radius][:attributes].delete :username
    end
    if data[:radsec] && data[:radsec][:attributes] && data[:radsec][:attributes][:username]
      logger.trace "Username from Radsec #{data[:radsec][:attributes][:username]}"
      username = data[:radsec][:attributes][:username]
      data[:radsec][:attributes].delete :username
    end
    if data[:eap] && data[:eap][:information] && data[:eap][:information][:eap_identity]
      logger.trace "Username from EAP #{data[:eap][:information][:eap_identity]}"
      username ||= data[:eap][:information][:eap_identity]
      data[:eap][:information].delete :eap_identity
    end
    username ||= ''

    username_parts = username.split('@')
    realm = if username_parts.length == 1
              'NOREALM.NOTLD'
            elsif username_parts.length > 2
              logger.warn "Found username with multiple realms: #{username} - Using the last one"
              username_parts.last
            else
              username_parts.last
            end

    mac = 'ff:ff:ff:ff:ff:ff'
    if data[:radius] && data[:radius][:attributes] && data[:radius][:attributes][:mac]
      logger.trace "MAC from RADIUS #{data[:radius][:attributes][:mac]}"
      mac = data[:radius][:attributes][:mac]
      data[:radius][:attributes].delete :mac
    end
    if data[:radsec] && data[:radsec][:attributes] && data[:radsec][:attributes][:mac]
      logger.trace "MAC from Radsec #{data[:radsec][:attributes][:mac]}"
      mac = data[:radsec][:attributes][:mac]
      data[:radsec][:attributes].delete :mac
    end

    meta = {}
    meta[:last_seen] = Time.now.utc.iso8601
    # TODO: THIS IS THE SCHEME AND CAPTURE VERSION.
    #   THIS SHOULD DEFINITELY BE CONFIGURABLE OR AT LEST SIT
    #   AT A MORE VISIBLE POINT OF THE CODE, SO IT CAN BE
    #   CHANGED EASILY IF THE VERSIONS NEED TO BE BUMPED
    meta[:scheme_ver] = 6
    meta[:capture_ver] = 4
    meta[:realm] = realm.downcase
    meta[:realm_tld] = meta[:realm].split('.').last
    meta[:oui] = mac.split(':')[0,3].join ':'
    meta[:vendor] = MacVendor.by_oid(meta[:oui])

    data[:meta] = meta

    to_insert = { id: nil, data: data }
    to_insert[:id] = Digest::SHA2.hexdigest "#{username}#{mac}"
    to_insert
  end

  # Inserts data into Elasticsearch
  # @param raw_data [Hash] Hash with data to insert.
  # @param debug [Boolean] If set to true the data will be printed on stdout. Defaults to false.
  # @param no_direct_elastic [Boolean] If set to true, the data will not be written in elastic. Defaults to false.
  # @param output_to_file [Boolean] If set to true, the data will be written in a File named <id>.json.
  #   Defaults to false.
  # @return nil
  def self.insert_into_elastic(raw_data, debug = false, no_direct_elastic = false, output_to_file = false, online_check = true)
    to_ins = ElasticHelper.convert_data_to_elasticsearch(raw_data)
    elastic_exists = ElasticHelper.check_exists to_ins[:id], online_check
    if ElasticHelper.bulk_insert
      ElasticHelper.bulk_data << to_ins
      if ElasticHelper.bulk_data.length >= ElasticHelper.bulk_insert
        begin
          unless no_direct_elastic
            bulk_data = ElasticHelper.bulk_data.map { |x| { index: { _id: x[:id], data: x[:data] } } }
            ElasticHelper.client.bulk index: 'tlshandshakes', body: bulk_data
          end
        rescue => e
          logger.warn 'Error in Bulk indexing.', e
          filename = File.join('debugcapture', "elasticbulk_#{DateTime.now.strftime('%s')}.txt")
          logger.warn "Writing elastic bulk insert to #{filename}"
          File.write(filename, ElasticHelper.bulk_data.inspect)
        end
        ElasticHelper.clear_bulk_data
      end
    else
      ElasticHelper.client.index index: 'tlshandshakes',
                                 id: to_ins[:id], body: to_ins[:data] unless no_direct_elastic
    end
    if elastic_exists
      StatHandler.increase(:elastic_update)
    elsif !online_check
      StatHandler.increase(:elastic_nolive)
    else
      StatHandler.increase(:elastic_new)
    end
    puts to_ins if debug
    File.write(File.join('data', to_ins[:id]),to_ins[:data].to_s) if output_to_file
    nil
  end

  # Flush the saved bulk inserts.
  # Should only be called to flush the queue on script exit
  def self.flush_bulk
    bulk_data = ElasticHelper.bulk_data.map { |x| { index: { _id: x[:id], data: x[:data] } } }
    ElasticHelper.client.bulk index: 'tlshandshakes', body: bulk_data
    ElasticHelper.clear_bulk_data
  end
end

