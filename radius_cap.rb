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




require_relative './includes'

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []
# @config[:socket_files] ||= ['/tmp/radsecproxy.sock']  # Not used in radius_cap.rb
@config[:ignoreips] ||= []

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
logger.info('Requirements done. Loading radius_cap.rb functions')

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

require_relative './inc/elastic_write'

logger.info('Start Packet parsing thread')

require_relative './inc/pcap_match'

require_relative './inc/stat_pcap'

pcap_file = PacketFu::PcapNG::File.new
pcap_array = pcap_file.file_to_array(filename: '/home/rieckers/hmt.pcapng')
pcap_id = 0
pcap_array.each do |p|

#logger.info('Start Packet capture')
#iface = PacketFu::Utils.default_int
#cap = Capture.new(iface: iface, start: true, filter: 'port 1812')
#begin
#  cap.stream.each do |p|
    pcap_id += 1
    puts "Packet #{pcap_id}"
    puts p.inspect
    logger.trace('Packet captured.')
    StatHandler.increase :packet_captured
    BlackBoard.pktbuf.synchronize do
      BlackBoard.pktbuf.push p
      BlackBoard.pktbuf_empty.signal
    end
  end
#rescue SignalException
#  logger.info('Captured Interrupt')
#end

BlackBoard.pktbuf.synchronize do
BlackBoard.pktbuf_empty.signal
end
gets

BlackBoard.pktbuf.synchronize do
BlackBoard.pktbuf_empty.signal
end
gets

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

# We should leave the parser thread a short time to finish the parsing, before we look for an empty elastic queue
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
