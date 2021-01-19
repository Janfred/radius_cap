#!/usr/bin/env ruby

require_relative './includes'

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []
#@config[:socket_files] ||= ['/tmp/radsecproxy.sock']  # Not used in radius_cap.rb

SemanticLogger.default_level = @config[:debug_level]
SemanticLogger.add_appender(file_name: 'development.log')
SemanticLogger.add_appender(io: STDOUT, formatter: :color) if @config[:debug]
SemanticLogger.add_appender(file_name: 'policy_violation.log', filter: /PolicyViolation/)
SemanticLogger.add_appender(file_name: 'statistics.log', filter: /StatHandler/)

logger = SemanticLogger['radius_cap']
policylogger = SemanticLogger['PolicyViolation']
logger.info("Requirements done. Loading radius_cap.rb functions")

class EAPFragParseError < StandardError
end
include PacketFu

BlackBoard.logger = logger
BlackBoard.pktbuf = []
BlackBoard.pktbuf.extend(MonitorMixin)
BlackBoard.pktbuf_empty = BlackBoard.pktbuf.new_cond
BlackBoard.policy_logger = policylogger

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
rescue Interrupt
  logger.info("Captured Interrupt")
end

logger.info("Terminating Capture")

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

logger.info("Elastic buffer is empty.")
logger.info("Terminating.")
