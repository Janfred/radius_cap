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

ElasticHelper.initialize_elasticdata @config[:debug]

Thread.start do
  loop do
    begin
      ElasticHelper.elasticdata.synchronize do
        ElasticHelper.waitcond.wait_while { ElasticHelper.elasticdata.empty? }
        toins = ElasticHelper.elasticdata.shift

        logger.trace 'To insert: ' + toins.to_s

        username = nil
        mac = nil
        if toins[:radius] && toins[:radius][:attributes] && toins[:radius][:attributes][:username]
          username = toins[:radius][:attributes][:username]
          logger.trace 'Username from RADIUS ' + username
        end
        if toins[:radius] && toins[:radius][:attributes] && toins[:radius][:attributes][:mac]
          mac = toins[:radius][:attributes][:mac]
          logger.trace 'MAC from RADIUS ' + mac
        end

        filters = @config[:elastic_filter].select { |x|
          (x[:username].nil? || username.nil? || x[:username] == username) &&
              (x[:mac].nil? || mac.nil? || x[:mac] == mac)
        }

        if filters.length == 0
          ElasticHelper.insert_into_elastic(toins, @config[:debug], @config[:noelastic], @config[:filewrite])
        else
          logger.debug 'Filtered out the Elasticdata'
        end
      end
    rescue => e
      logger.error("Error in Elastic Write", exception: e)
    end
  end
end

logger.info("Start Packet parsing thread")
Thread.start do
  loop do
    BlackBoard.pktbuf.synchronize do
      BlackBoard.pktbuf_empty.wait_while { BlackBoard.pktbuf.empty? }
      p = BlackBoard.pktbuf.shift
      pkt = Packet.parse p
      # Skip all packets other then ip
      next unless pkt.is_ip?
      # Skip all fragmented ip packets
      next if pkt.ip_frag & 0x2000 != 0
      # only look on copied packets
      next if ([pkt.ip_daddr, pkt.ip_saddr] & @config[:ipaddrs]).empty?
      # Skip packets with ignored ip addresses
      next unless ([pkt.ip_daddr, pkt.ip_saddr] & @config[:ignoreips]).empty?
      # Skip non-udp packets
      next unless pkt.is_udp?
      # Skip packets for other port then radius
      next unless [pkt.udp_sport, pkt.udp_dport].include? 1812

      # Print out debug info, just for now to monitor progress
      packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      #puts "%-15s -> %-15s %-4d %s" % packet_info

      rp = nil

      begin
        # Parse Radius packets
        rp = RadiusPacket.new(pkt)
        rp.check_policies
      rescue PacketLengthNotValidError => e
        puts "PacketLengthNotValidError!"
        puts e.message
        puts e.backtrace.join "\n"
        puts p.unpack("H*").first
        $stderr.puts e.message
        next
      rescue ProtocolViolationError => e
        policylogger.info e.class.to_s + ' ' + e.message + ' From: ' + pkt.ip_saddr + ' To: ' + pkt.ip_daddr + ' Realm: ' + (pkt.realm || "")
      rescue PolicyViolationError => e
        policylogger.info e.class.to_s + ' ' + e.message + ' From: ' + pkt.ip_saddr + ' To: ' + pkt.ip_daddr + ' Realm: ' + (pkt.realm || "")
      rescue => e
        puts "General error in Parsing!"
        puts e.message
        puts e.backtrace.join "\n"
        puts p.unpack("H*").first
        next
      end

      next if rp.nil?

      begin
        RadiusStreamHelper.add_packet(rp)
      rescue PacketFlowInsertionError => e
        logger.warn 'PacketFlowInsertionError: ' + e.message
      rescue => e
        puts "Error in Packetflow!"
        puts e.message
        puts e.backtrace.join "\n"
      end
    end
  end
end

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
