#!/usr/bin/env ruby

require_relative './includes'

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []
@config[:socket_files] ||= [{path: '/tmp/radsecproxy.sock', label: 'radsecproxy'}]

SemanticLogger.default_level = @config[:debug_level]
SemanticLogger.add_appender(file_name: 'development.log')
SemanticLogger.add_appender(io: STDOUT, formatter: :color) if @config[:debug]
SemanticLogger.add_appender(file_name: 'policy_violation.log', level: :debug, filter: /PolicyViolation/)
SemanticLogger.add_appender(file_name: 'statistics.log', level: :debug, filter: /StatHandler/)

logger = SemanticLogger['radius_cap']
policylogger = SemanticLogger['PolicyViolation']
logger.info("Requirements done. Loading radsecproxy_cap.rb functions")





BlackBoard.logger = logger
BlackBoard.pktbuf = []
BlackBoard.pktbuf.extend(MonitorMixin)
BlackBoard.pktbuf_empty = BlackBoard.pktbuf.new_cond
BlackBoard.policy_logger = policylogger

require_relative './inc/elastic_write.rb'

logger.info("Start Packet parsing")

require_relative './inc/packet_match.rb'

require_relative './inc/stat_radsec.rb'

require_relative './inc/sock_read.rb'

BlackBoard.sock_threads = []
logger.info("Start Packet capture")
begin
  @config[:socket_files].each do |path|
    sock_read(path[:path], path[:label])
  end
  sleep

rescue Interrupt
  logger.info("Capture Interrupt. Aborting capture")
  BlackBoard.sock_threads.each do |thr|
    thr[:watchdog].exit
    thr.exit
  end
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
logger.info("Saving stat")
StatHandler.write_temp_stat

logger.info("Terminating.")
