#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

# Require needed gems
require 'packetfu'
require 'irb'
require 'monitor'
require 'semantic_logger'

# Require local files
require './radiuspacket.rb'
require './eappacket.rb'
require './tlsclienthello.rb'
require './tlsserverhello.rb'
require './localconfig.rb'
require './write_to_elastic.rb'
require './macvendor.rb'
require './radiusstream.rb'
require './eapstream.rb'
require './stackparser.rb'
require './tlsstream.rb'

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []

SemanticLogger.default_level = @config[:debug_level]
SemanticLogger.add_appender(file_name: 'development.log')
SemanticLogger.add_appender(io: STDOUT, formatter: :color) if @config[:debug]

logger = SemanticLogger['radius_cap']

logger.info("Requirements done. Loading radius_cap.rb functions")

class EAPFragParseError < StandardError
end

include PacketFu

pktbuf = []
pktbuf.extend(MonitorMixin)
empty_cond = pktbuf.new_cond

ElasticHelper.initialize_elasticdata @config[:debug]

Thread.start do
  loop do
    ElasticHelper.elasticdata.synchronize do
      ElasticHelper.waitcond.wait_while { ElasticHelper.elasticdata.empty? }
      toins = ElasticHelper.elasticdata.shift

      username = nil
      mac = nil
      if toins[:radius] && toins[:radius][:attributes] && toins[:radius][:attributes][:username]
        username = toins[:radius][:attributes][:username]
      end
      if toins[:radius] && toins[:radius][:attributes] && toins[:radius][:attributes][:mac]
        mac = toins[:radius][:attributes][:mac]
      end

      if @config[:elastic_filter].filter { |x|
        (x[:username].nil? || username.nil? || x[:username] == username) &&
            (x[:mac].nil? || mac.nil? || x[:mac] == mac)
      }
      end

      insert_into_elastic(toins, @config[:debug], @config[:noelastic], @config[:filewrite])
    end
  end
end

logger.info("Start Packet parsing thread")
Thread.start do
  loop do
    pktbuf.synchronize do
      empty_cond.wait_while { pktbuf.empty? }
      p = pktbuf.shift
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
          #puts rp.inspect
          #binding.irb
      rescue PacketLengthNotValidError => e
        ##################################################
        # THIS IS A CASE THAT SHOULDN'T OCCUR.           #
        # IT SHOULD BE CATCHED BY THE FRAGMENT STATEMENT #
        ##################################################
        # TODO: Remove irb binding
        puts "PacketLengthNotValidError!"
        puts e.message
        puts e.backtrace.join "\n"
        puts p.unpack("H*").first
        $stderr.puts e.message
          #binding.irb
      rescue => e
        # This is here for debugging.
        # TODO: remove irb binding
        puts "General error in Parsing!"
        puts e.message
        puts e.backtrace.join "\n"
        puts p.unpack("H*").first
        #binding.irb
      end
      begin
        RadiusStreamHelper.add_packet(rp)
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
    pktbuf.synchronize do
      pktbuf.push p
      empty_cond.signal
    end
  end
rescue Interrupt
  logger.info("Captured Interrupt")
end

logger.info("Terminating Capture")

logger.info("Waiting for empty packet buffer")

pktbufempty = false
until pktbufempty do
  pktbuf.synchronize do
    pktbufempty = pktbuf.empty?
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
