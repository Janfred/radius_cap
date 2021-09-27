#!/usr/bin/env ruby
# frozen_string_literal: true

################################################################################
#    radius_cap, a RADIUS EAP-TLS analysis software                            #
#    Copyright (C) 2018-2021  Jan-Frederik Rieckers <rieckers@uni-bremen.de>   #
#                                                                              #
#    This program is free software: you can redistribute it and/or modify      #
#    it under the terms of the GNU General Public License as published by      #
#    the Free Software Foundation, either version 3 of the License, or         #
#    (at your option) any later version.                                       #
#                                                                              #
#    This program is distributed in the hope that it will be useful,           #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of            #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
#    GNU General Public License for more details.                              #
#                                                                              #
#    You should have received a copy of the GNU General Public License         #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.    #
################################################################################


@nopacketfu = true

require_relative './includes'

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []
@config[:socket_files] ||= [{ path: '/tmp/radsecproxy.sock', label: 'radsecproxy' }]

SemanticLogger.default_level = :debug
SemanticLogger.add_appender(file_name: 'development.log', level: @config[:debug_level])
SemanticLogger.add_appender(io: $stdout, formatter: :color, level: @config[:debug_level]) if @config[:debug]
SemanticLogger.add_appender(file_name: 'policy_violation.log', level: :debug, filter: /PolicyViolation/)
SemanticLogger.add_appender(file_name: 'statistics.log', level: :debug, filter: /StatHandler/)
SemanticLogger.add_appender(file_name: 'policy_violation_detail.log', level: :debug, filter: /PolicyDetailViolation/)

BlackBoard.config=@config

logger = SemanticLogger['radius_cap']
policylogger = SemanticLogger['PolicyViolation']
policydetaillogger = SemanticLogger['PolicyDetailViolation']
logger.info('Requirements done. Loading radsecproxy_cap.rb functions')







BlackBoard.logger = logger
BlackBoard.pktbuf = []
BlackBoard.pktbuf.extend(MonitorMixin)
BlackBoard.pktbuf_empty = BlackBoard.pktbuf.new_cond
BlackBoard.policy_logger = policylogger
BlackBoard.policy_detail_logger = policydetaillogger

ElasticHelper.bulk_insert = @config[:bulk_insert]

require_relative './inc/elastic_write'

logger.info('Start Packet parsing')

require_relative './inc/packet_match'

require_relative './inc/stat_radsec'

require_relative './inc/sock_read'

BlackBoard.sock_threads = []
logger.info('Start Packet capture')
begin
  @config[:socket_files].each do |path|
    sock_read(path[:path], path[:label])
  end
  sleep

rescue SignalException
  logger.info('Capture Interrupt. Aborting capture')
  BlackBoard.sock_threads.each do |thr|
    thr[:watchdog].exit
    thr.exit
  end
end

logger.info('Terminating Capture')

logger.info('Waiting for empty packet buffer')

pktbufempty = false
until pktbufempty
  BlackBoard.pktbuf.synchronize do
    pktbufempty = BlackBoard.pktbuf.empty?
  end
  sleep 1
end

logger.info('Packet buffer is empty.')
# We should leave the parser thread a short time to finish the parsing, before we look for an empty elastic queue
sleep 0.5

logger.info('Waiting for empty parser buffer')

parserempty = false
until parserempty
  StackParser.instance.priv_stack_data.synchronize do
    parserempty = StackParser.instance.priv_stack_data.empty?
  end
  sleep 1
end

logger.info('Parser buffer is empty.')

sleep 0.5

logger.info('Waiting for empty elastic buffer')

elasticempty = false
until elasticempty
  ElasticHelper.elasticdata.synchronize do
    elasticempty = ElasticHelper.elasticdata.empty?
  end
  sleep 1
end

begin
  ElasticHelper.flush_bulk
rescue StandardError
  # left blank intentionally
end

logger.info('Elastic buffer is empty.')
logger.info('Saving stat')
StatHandler.write_temp_stat

logger.info('Terminating.')
