#!/usr/bin/env ruby

require 'packetfu'
require 'irb'
require './radiuspacket.rb'


include PacketFu

iface = PacketFu::Utils.default_int

cap = Capture.new(:iface => iface, :start => true)
cap.stream.each do |p|
  pkt = Packet.parse p
  if pkt.is_ip?
#    next if ([pkt.ip_daddr, pkt.ip_saddr] & ['10.11.0.216', '10.11.0.217']).empty?
    next unless pkt.is_udp?
    next unless [pkt.udp_sport, pkt.udp_dport].include? 1812
    packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
    puts "%-15s -> %-15s %-4d %s" % packet_info
    if pkt.is_udp?
      @p = pkt
      binding.irb
    end
  end
end
