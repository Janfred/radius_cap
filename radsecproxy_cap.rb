#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

# Require needed gems
require 'socket'
require 'irb'
require 'monitor'
require 'semantic_logger'

require 'singleton'
require 'openssl'

# Require local files
require_relative './src/blackboard.rb'
require_relative './src/stat_handler.rb'
require_relative './src/radiuspacket.rb'
require_relative './src/eappacket.rb'
require_relative './src/tlsclienthello.rb'
require_relative './src/tlsserverhello.rb'
require_relative './localconfig.rb'
require_relative './src/write_to_elastic.rb'
require_relative './src/macvendor.rb'
require_relative './src/radiusstream.rb'
require_relative './src/radsecstream.rb'
require_relative './src/eapstream.rb'
require_relative './src/stackparser.rb'
require_relative './src/tlsstream.rb'

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []
@config[:socket_files] ||= ['/tmp/radsecproxy.sock']

SemanticLogger.default_level = @config[:debug_level]
SemanticLogger.add_appender(file_name: 'development.log')
SemanticLogger.add_appender(io: STDOUT, formatter: :color) if @config[:debug]
SemanticLogger.add_appender(file_name: 'policy_violation.log', filter: /PolicyViolation/)
SemanticLogger.add_appender(file_name: 'statistics.log', filter: /StatHandler/)

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

require_relative './inc/stat.rb'

require_relative './inc/sock_read.rb'

BlackBoard.sock_threads = []
logger.info("Start Packet capture")
begin
  @config[:socket_files].each do |path|
    sock_read(path)
  end
  sleep

rescue Interrupt
  logger.info("Capture Interrupt. Aborting capture")
  BlackBoard.sock_threads.each do |thr|
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
logger.info("Terminating.")
