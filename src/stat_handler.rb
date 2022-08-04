# frozen_string_literal: true

require 'json'
require 'time'

# Class for handling statistics
class StatHandler
  include SemanticLogger::Loggable
  include Singleton

  # Create new instance of the StatHandler class
  def initialize
    @stat_history = []
    @stat_history.extend(MonitorMixin)
    @statistics = {}
    @statistics.extend(MonitorMixin)
    @stat_items = %i[
      packet_captured
      packet_analyzed
      packet_errored
      packet_elastic_filtered
      packet_elastic_written
      packet_timed_out
      elastic_writes
      elastic_new
      elastic_filters
      elastic_update
      elastic_nolive
      streams_timed_out
      streams_analyzed
      streams_errored
      streams_written
      streams_skipped
      eaperror_first_not_identity
      eaperror_communication_too_short
      eaperror_other
      eaperror_unexpected_end
      pkterror_reply_on_reply
      pkterror_multiple_state
      pkterror_no_state_found
      pkterror_multiple_requests
    ]
    @statistics.synchronize do
      null_stat
    end
    no_stat_server = BlackBoard.config && BlackBoard.config[:no_stat_server]
    unless no_stat_server
      if File.exist?('stat_tmp')
        data = JSON.parse(File.read('stat_tmp'))
        thres = Time.now - 3600
        data.shift while !data.empty? && Time.parse(data[0]['timestamp']) < thres
        data.each do |d|
          @stat_history << d
        end
      end
      @stat_server_thr = start_stat_server
    end
  end

  # Private function for adding stat
  # @param symb [Symbol]
  # @private
  def priv_add_stat_item(symb)
    @stat_items << symb
    @statistics.synchronize do
      @statistics[symb] ||= 0
    end
  end

  # Add a statistic item
  # @param symb [Symbol] Statistics Symbol to add to statistics
  def self.add_stat_item(symb)
    StatHandler.instance.priv_add_stat_item(symb)
  end

  # Write Statistics Temp File (e.g. before a shutdown)
  def self.write_temp_stat
    StatHandler.instance.priv_write_temp_stat
  end

  # Private function for stat temp file
  def priv_write_temp_stat
    File.write('stat_tmp', @stat_history.to_json)
  end

  # Start a TCP Statistic Server for Munin Statistics
  # @todo currently fixed on port 6898, should be configurable
  def start_stat_server
    Thread.start do
      server = TCPServer.new '127.0.0.1', 6898
      loop do
        Thread.start(server.accept) do |client|
          @stat_history.synchronize do
            client.write (@stat_history.length >= 15 ? @stat_history[-15, 15] : @stat_history).to_json
            client.close
          end
        end
      end
    end
    Thread.start do
      server = TCPServer.new '127.0.0.1', 6897
      loop do
        Thread.start(server.accept) do |client|
          stat = {}
          ElasticHelper.elasticdata.synchronize do
            stat[:elastic_length] = ElasticHelper.elasticdata.length
          end
          BlackBoard.pktbuf.synchronize do
            stat[:pktbuf_length] = BlackBoard.pktbuf.length
          end
          StackParser.instance.priv_stack_data.synchronize do
            stat[:stack_length] = StackParser.instance.priv_stack_data.length
          end
          stat[:known_streams] = RadsecStreamHelper.instance.known_streams.length

          client.write stat.to_json
          client.close
        end
      end
    end
  end

  # Reset the value of all statistic symbols to 0
  def null_stat

    (@stat_items | @statistics.keys).each do |item|
      @statistics[item] = 0
    end

  end

  # Private function for increasing a field value
  def priv_increase(field,num)
    @statistics.synchronize do
      @statistics[field] ||= 0
      @statistics[field] += num
    end
  end

  # Increase a given statistic field by a given value
  # @param field [Symbol] Statistics field to increase
  # @param num [Integer] value by which field will be increased, defaults to 1
  def self.increase(field,num=1)
    StatHandler.instance.priv_increase(field,num)
  end

  # Private function for getting field values
  def priv_get_values(field)
    to_ret = []
    @stat_history.synchronize do
      @stat_history.each do |s|
        to_ret << s[field]
      end
    end
    @statistics.synchronize do
      to_ret << @statistics[field]
    end
  end

  # Get values for a given field for the last 60 minutes
  # @param field [Symbol] Statistics field to query
  # @return [Array<Integer>] last 60 values as int array, values may be nil
  def self.get_values(field)
    StatHandler.instance.priv_get_values(field)
  end

  # Private function for logging the current statistics
  def priv_log_stat

    if BlackBoard.config[:profiler]
      timestamp = Time.now.to_i.to_s
      # Create Folder
      Dir.mkdir(File.join('statistics', timestamp))
      BlackBoard.profilers.each do |k,v|
        File.write(File.join('statistics', timestamp, k), v.report)
      end
    end

    logmsg = ''
    cur_stat = {}
    @statistics.synchronize do
      logmsg += "Pkt Capture: #{@statistics[:packet_captured]}"
      logmsg += " Pkt Analyze: #{@statistics[:packet_analyzed]}"
      logmsg += " Pkt Errored: #{@statistics[:packet_errored]}"
      logmsg += " Pkt Elastic: #{@statistics[:packet_elastic_written]}"
      logmsg += " Pkt FilterE: #{@statistics[:packet_elastic_filtered]}"
      logmsg += " Pkt Timeout: #{@statistics[:packet_timed_out]}"
      logmsg += ' ---'
      logmsg += " Stream analyze: #{@statistics[:streams_analyzed]}"
      logmsg += " Stream timeout: #{@statistics[:streams_timed_out]}"
      logmsg += ' ---'
      logmsg += " Elastic writes: #{@statistics[:elastic_writes]}"
      logmsg += " Elastic filter: #{@statistics[:elastic_filters]}"

      @stat_items.each do |i|
        cur_stat[i] = @statistics[i]
      end
      cur_stat['timestamp'] = Time.now.strftime('%Y-%m-%dT%H:%M')
      null_stat
      @stat_history.synchronize do
        @stat_history << cur_stat
        @stat_history.shift @stat_history.length - 60 if @stat_history.length > 60
      end
    end
    logger.debug logmsg
  end

  # Log current statistic values and save current stat to history
  def self.log_stat
    StatHandler.instance.priv_log_stat
  end

  # Private function to log additional statistic data
  def priv_log_additional(logmsg)
    logger.debug logmsg
  end

  # Log a message to the statistics logger
  # @param logmsg [String] Log message to log to statistics logger
  def self.log_additional(logmsg)
    StatHandler.instance.priv_log_additional logmsg
  end
end
