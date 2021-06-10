#!/usr/bin/env ruby

require_relative './includes'

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []
#@config[:socket_files] ||= ['/tmp/radsecproxy.sock']  # Not used in radius_cap.rb

SemanticLogger.default_level = :debug
SemanticLogger.add_appender(file_name: 'development.log', level: @config[:debug_level])
SemanticLogger.add_appender(io: STDOUT, formatter: :color, level: @config[:debug_level]) if @config[:debug]
SemanticLogger.add_appender(file_name: 'policy_violation.log', level: :debug, filter: /PolicyViolation/)
SemanticLogger.add_appender(file_name: 'statistics.log', level: :debug, filter: /StatHandler/)
SemanticLogger.add_appender(file_name: 'policy_violation_detail.log', level: :debug, filter: /PolicyDetailViolation/)

logger = SemanticLogger['radius_cap']
policylogger = SemanticLogger['PolicyViolation']
policydetaillogger = SemanticLogger['PolicyDetailViolation']
logger.info("Requirements done. Loading radius_cap.rb functions")

# Error to be thrown if the EAP Packet fragmentation causes an error
# @todo this definition should be moved to an appropriate place
class EAPFragParseError < StandardError
end
include PacketFu

BlackBoard.logger = logger
BlackBoard.pktbuf = []
BlackBoard.pktbuf.extend(MonitorMixin)
BlackBoard.pktbuf_empty = BlackBoard.pktbuf.new_cond
BlackBoard.policy_logger = policylogger
BlackBoard.policy_detail_logger = policydetaillogger

ElasticHelper.bulk_insert = @config[:bulk_insert]

require_relative './inc/elastic_write.rb'

logger.info("Start Packet parsing thread")

require_relative './inc/pcap_match.rb'

require_relative './inc/stat_pcap.rb'

#pcap_file = PacketFu::PcapNG::File.new
#pcap_array = pcap_file.file_to_array(filename: './debugcapture2.pcapng')
#pcap_id = 0
#pcap_array.each do |p|

logger.info("Start Packet capture")
iface = PacketFu::Utils.default_int
cap = Capture.new(:iface => iface, :start => true, :filter => 'port 1812')
begin
  cap.stream.each do |p|
#    pcap_id += 1
#    puts "Packet #{pcap_id}"
    logger.trace("Packet captured.")
    StatHandler.increase :packet_captured
    BlackBoard.pktbuf.synchronize do
      BlackBoard.pktbuf.push p
      BlackBoard.pktbuf_empty.signal
    end
  end
rescue SignalException
  logger.info("Captured Interrupt")
end

logger.info("Terminating Capture")

logger.info("Waiting for empty parser buffer")

parserempty = false
until parserempty do
  StackParser.instance.priv_stack_data.synchronize do
    parserempty = StackParser.instance.priv_stack_data.empty?
  end
  sleep 1
end

logger.info("Parser buffer is empty.")

sleep 0.5

logger.info("Waiting for empty packet buffer")

pktbufempty = false
until pktbufempty do
  BlackBoard.pktbuf.synchronize do
    pktbufempty = BlackBoard.pktbuf.empty?
  end
  sleep 1
end

logger.info("Packet buffer is empty.")
# We should leave the parser thread a short time to finish the parsing, before we look for an empty elastic queue
sleep 0.5
logger.info("Waiting for empty elastic buffer")

elasticempty = false
until elasticempty do
  ElasticHelper.elasticdata.synchronize do
    elasticempty = ElasticHelper.elasticdata.empty?
  end
  sleep 1
end

ElasticHelper.flush_bulk

logger.info("Elastic buffer is empty.")
logger.info("Saving stat")
StatHandler.write_temp_stat

logger.info("Terminating.")
