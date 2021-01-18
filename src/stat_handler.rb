require 'json'

class StatHandler
  include SemanticLogger::Loggable
  include Singleton

  def initialize
    @stat_history=[]
    @stat_history.extend(MonitorMixin)
    @statistics={}
    @statistics.extend(MonitorMixin)
    @statistics.synchronize do
      null_stat
    end
    @stat_server_thr = start_stat_server
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

    @statistics[:packet_captured] = 0
    @statistics[:packet_analyzed] = 0
    @statistics[:packet_errored] = 0
    @statistics[:packet_elastic_written] = 0
    @statistics[:packet_elastic_filtered] = 0
    @statistics[:packet_timed_out] = 0

    @statistics[:elastic_writes] = 0
    @statistics[:elastic_filters] = 0

    @statistics[:streams_timed_out] = 0
    @statistics[:streams_analyzed] = 0

    @statistics[:elastic_update] = 0
    @statistics[:elastic_new] = 0

  end

  def priv_increase(field,num)
    @statistics.synchronize do
      @statistics[field] += num
    end
  end
  def self.increase(field,num=1)
    StatHandler.instance.priv_increase(field,num)
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

      [:packet_captured, :packet_analyzed, :packet_errored, :packet_elastic_written, :packet_elastic_filtered,
       :packet_timed_out, :streams_analyzed, :streams_timed_out, :elastic_writes, :elastic_filters].each do |i|
        cur_stat[i] = @statistics[i]
      end
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