require 'json'
require 'time'

class StatHandler
  include SemanticLogger::Loggable
  include Singleton

  def initialize
    @stat_history=[]
    @stat_history.extend(MonitorMixin)
    @statistics={}
    @statistics.extend(MonitorMixin)
    @stat_items = [
      :packet_captured,
      :packet_analyzed,
      :packet_errored,
      :packet_elastic_filtered,
      :packet_elastic_written,
      :packet_timed_out,
      :elastic_writes,
      :elastic_new,
      :elastic_filters,
      :elastic_update,
      :streams_timed_out,
      :streams_analyzed,
      :streams_errored,
      :streams_written,
      :streams_skipped,
    ]
    @statistics.synchronize do
      null_stat
    end
    if File.exists?('stat_tmp')
      data = JSON.parse(File.read('stat_tmp'))
      thres = Time.now - 3600
      data.shift while data.length > 0 && Time.parse(data[0]["timestamp"]) < thres
      data.each do |d|
        @stat_history << d
      end
    end
    @stat_server_thr = start_stat_server
  end

  def priv_add_stat_item(symb)
    @stat_items << symb
    @statistics.synchronize do
      @statistics[symb] ||= 0
    end
  end

  def self.add_stat_item(symb)
    StatHandler.instance.priv_add_stat_item(symb)
  end

  def self.write_temp_stat
    StatHandler.instance.priv_write_temp_stat
  end
  def priv_write_temp_stat
    File.write('stat_tmp', @stat_history.to_json)
  end

  def start_stat_server
    Thread.start do
      server = TCPServer.new '127.0.0.1', 6898
      loop do
        Thread.start(server.accept) do |client|
          @stat_history.synchronize do
            client.write (@stat_history.length >= 15 ? @stat_history[-15,15] : @stat_history).to_json
            client.close
          end
        end
      end
    end
  end

  def null_stat

    (@stat_items | @statistics.keys).each do |item|
      @statistics[item] = 0
    end

  end

  def priv_increase(field,num)
    @statistics.synchronize do
      @statistics[field] ||= 0
      @statistics[field] += num
    end
  end
  def self.increase(field,num=1)
    StatHandler.instance.priv_increase(field,num)
  end

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
  def self.get_values(field)
    StatHandler.instance.priv_get_values(field)
  end

  def priv_log_stat
    logmsg = ""
    cur_stat = {}
    @statistics.synchronize do
      logmsg +=  "Pkt Capture: #{@statistics[:packet_captured]}"
      logmsg += " Pkt Analyze: #{@statistics[:packet_analyzed]}"
      logmsg += " Pkt Errored: #{@statistics[:packet_errored]}"
      logmsg += " Pkt Elastic: #{@statistics[:packet_elastic_written]}"
      logmsg += " Pkt FilterE: #{@statistics[:packet_elastic_filtered]}"
      logmsg += " Pkt Timeout: #{@statistics[:packet_timed_out]}"
      logmsg += " ---"
      logmsg += " Stream analyze: #{@statistics[:streams_analyzed]}"
      logmsg += " Stream timeout: #{@statistics[:streams_timed_out]}"
      logmsg += " ---"
      logmsg += " Elastic writes: #{@statistics[:elastic_writes]}"
      logmsg += " Elsatic filter: #{@statistics[:elastic_filters]}"

      @stat_items.each do |i|
        cur_stat[i] = @statistics[i]
      end
      cur_stat["timestamp"] = Time.now.strftime('%Y-%m-%dT%H:%M')
      null_stat
      @stat_history.synchronize do
        @stat_history << cur_stat
        if @stat_history.length > 60
          @stat_history.shift @stat_history.length-60
        end
      end
    end
    logger.info logmsg
  end

  def self.log_stat
    StatHandler.instance.priv_log_stat
  end
  def priv_log_additional(logmsg)
    logger.info logmsg
  end
  def self.log_additional(logmsg)
    StatHandler.instance.priv_log_additional logmsg
  end
end