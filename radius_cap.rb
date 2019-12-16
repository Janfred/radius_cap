#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'packetfu'
require 'irb'
require 'monitor'
require './radiuspacket.rb'
require './eappacket.rb'
require './tlsclienthello.rb'
require './tlsserverhello.rb'
require './localconfig.rb'
require './write_to_elastic.rb'

class EAPFragParseError < StandardError
end


include PacketFu

# This is for state saves.
# Syntax:
# {
#   last_updated: Timestamp, // when last seen (for timing out states)
#   state: [],               // current state (set on outgoing communication)
#   udp_data: {              // current udp data (set on incoming communication)
#     ip: IPAddr,            //   source ip addr
#     port: Port,            //   source udp port
#     id: Identifier         //   radius packet Id
#   },
#   pkt: []                  // Array of packets (in received order)
#
# }
@packetflow = []

def insert_in_packetflow(pkt)
  if(pkt.udp[:dst][:port] == 1812)
    # This is an incoming packet
    if pkt.state.nil?
      # Probably a completely new request
      state = {
        last_updated: Time.now,
        state: nil,
        udp_data: {
          ip: pkt.udp[:src][:ip],
          port: pkt.udp[:src][:port],
          id: pkt.identifier
        },
        pkt: [
          pkt
        ]
      }
      @packetflow << state
    else
      # Proxystate exists, so this is ongoing communication
      p = @packetflow.select{ |x| x[:state] == pkt.state }
      if p.empty?
        $stderr.puts "Could not find EAP state 0x#{pkt.state.pack('C*').unpack('H*').first}"
        return
      end
      if p.length > 1
        $stderr.puts "Found multiple EAP States for 0x#{pkt.state.pack('C*').unpack('H*').first}"
        return
      end
      flow = p.first
      flow[:last_updated] = Time.now
      flow[:pkt] << pkt
      flow[:udp_data] = {
        ip: pkt.udp[:src][:ip],
        port: pkt.udp[:src][:port],
        id: pkt.identifier
      }
    end
  else
    # We are a server, so communication will never be initiated by us.
    # But we are terminating the communication with Accept/Reject Packets.

    # First find matching state
    p = @packetflow.select { |x| x[:udp_data] == {ip: pkt.udp[:dst][:ip], port: pkt.udp[:dst][:port], id: pkt.identifier} }
    if p.empty?
      $stderr.puts "Could not find a matching request from #{pkt.udp[:dst][:ip]}:#{pkt.udp[:dst][:port]} and ID #{pkt.identifier}"
      return
    end
    if p.length > 1
      $stderr.puts "Found multiple requests from #{pkt.udp[:dst][:ip]}:#{pkt.udp[:dst][:port]} and ID #{pkt.identifier}"
    end
    flow = p.last

    # Now we check what we were sending
    if pkt.packettype == RadiusPacket::Type::ACCEPT || pkt.packettype == RadiusPacket::Type::REJECT
      # This is the final answer.

      flow[:pkt] << pkt

      # This Radius communication is finished. we can delete it from the current state
      @packetflow.delete flow

      # Hand over to EAP Parsing
      parse_eap(flow)
    else
      # This is ongoing communication
      if pkt.state.nil? then
        $stderr.puts "Outgoing communication without state set."
        return
      end
      flow[:last_updated] = Time.now
      flow[:state] = pkt.state
      flow[:pkt] << pkt
    end
  end

  # Now do housekeeping
  t = Time.now
  old = @packetflow.select { |x| (t-x[:last_updated]) > 10}
  old.each do |o|
    $stderr.puts "Timing out 0x#{o[:state].pack('C*').unpack('H*').first}" if o[:state]
    $stderr.puts "Timing out state without state variable" unless o[:state]
    @packetflow.delete o
  end
end

def normalize_mac(mac)
  mac.downcase!
  m_d = mac.match /^([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2})$/
  if m_d && m_d.length == 7 then
    return m_d[1,6].join ":"
  end
  return "ff:ff:ff:ff:ff:ff"
end

def parse_eap(data)
  #puts "------------------"
  #puts "EAP: Parsing data:"
  #puts data.inspect

  firstpkt = data[:pkt].first
  return if firstpkt.nil?
  username_a = firstpkt.attributes.select{|x| x[:type] == RadiusPacket::Attribute::USERNAME }
  return if username_a.length != 1
  username = username_a.first[:data].pack('C*')
  return if username.split("@").length != 2

  mac_a = firstpkt.attributes.select{|x| x[:type] == RadiusPacket::Attribute::CALLINGSTATIONID }
  return if mac_a.length != 1
  mac = mac_a.first[:data].pack('C*')

  # Normalize mac-address
  macaddr = normalize_mac(mac)

  elastic_data = {
    username: username,
    mac: macaddr,
    eapmethod: nil,
    tlsclienthello: nil,
    tlsserverhello: nil
  }

  eap = []
  data[:pkt].each do |p|
    next if p.eap.nil?
    eap << EAPPacket.new(p.eap)
  end

  if eap.empty?
    $stderr.puts "No EAP Packets present"
    return
  end
  # Initial EAP communication
  if (eap.first.code != EAPPacket::Code::RESPONSE || eap.first.type != EAPPacket::Type::IDENTITY) then
    $stderr.puts "First code was no EAP Response or Identity"
    return
  end
  identity = eap.first.type_data.pack('C*')

  supported_eap_method = false
  eap_method = 0

  eap_reply = nil
  while eap_reply.nil? || eap_reply.type == EAPPacket::Type::NAK do
    eap.shift
    if eap.length < 2 then
      # Length to short for EAP Method agreement, probably because of immediate reject
      return
    end
    # Initial eap handshake.
    # The Server offers a specific method (e.g. TTLS)
    # The Client can deny this (NAK) and send its own desired authentication mechanism
    eap_start = eap.shift
    case eap_start.type
      when EAPPacket::Type::TTLS,
           EAPPacket::Type::PEAP,
           EAPPacket::Type::TLS
        # Check if start flag is set
        if eap_start.length != 6 then
          $stderr.puts "Invalid length for EAP-TLS Start"
          return
        end
        if eap_start.type_data[0] != EAPPacket::TLSFlags::START
        end
        supported_eap_method = true
        eap_method = eap_start.type
      when EAPPacket::Type::EAPPWD,
           EAPPacket::Type::MD5CHALLENGE,
           EAPPacket::Type::MSEAP
        # These methods are not implemented.
        # The Client could still reply with a NAK, in this case we can
        # continue to parse.
        supported_eap_method = false
      else
        $stderr.puts "Unknown EAP Type #{eap_start.type}"
        return
    end
    eap_reply = eap.first
  end

  # If the client didn't NAK the unsupported method, we cant continue parsing
  return unless supported_eap_method

  elastic_data[:eapmethod] = case eap_method
    when EAPPacket::Type::TTLS; "TTLS";
    when EAPPacket::Type::PEAP; "PEAP";
    when EAPPacket::Type::TLS;  "TLS";
    else
      "Unknown"
  end

  eap_tls_clienthello = nil
  begin
    eap_tls_clienthello = read_eaptls_fragment(eap, eap_reply.type)
  rescue EAPFragParseError => e
    return
  end

  begin
    clienthello = TLSClientHello.new(eap_tls_clienthello)
  rescue TLSClientHelloError => e
    return
  end
  elastic_data[:tlsclienthello] = clienthello.to_h

  eap_tls_serverhello = nil
  begin
    eap_tls_serverhello = read_eaptls_fragment(eap, eap_reply.type)
  rescue EAPFragParseError => e
    return
  end

  begin
    serverhello = TLSServerHello.new(eap_tls_serverhello)
  rescue TLSServerHelloError => e
    return
  end
  elastic_data[:tlsserverhello] = serverhello.to_h

  ## Hier muss das ganze dann in elasticsearch gepumpt werden
  ElasticHelper.elasticdata.synchronize do
    ElasticHelper.elasticdata.push elastic_data
    ElasticHelper.waitcond.signal
  end
end

def read_eaptls_fragment(eap, eap_type)
  more_fragments = false
  length = nil
  data = []
  begin
    more_fragments = false
    frag = eap.shift
    if frag.nil? then
      $stderr.puts 'Reached end while scanning EAP Fragment'
      raise EAPFragParseError
    end
    if frag.type != eap_type then
      $stderr.puts 'Found fragment without matching eap type'
      raise EAPFragParseError
    end
    unless frag.type_data.length > 0 then
      $stderr.puts 'Empty fragment. Interesting.'
      raise EAPFragParseError
    end
    flags = frag.type_data[0]
    cur_ptr = 1
    if (flags & EAPPacket::TLSFlags::LENGTHINCLUDED) != 0 then
      ind_length = frag.type_data[1]*256*256*256 + frag.type_data[2]*256*256 + frag.type_data[3]*256 + frag.type_data[4]
      length ||= ind_length
      # If a length is included, it should be the same among all eap packets
      if length != ind_length
        $stderr.puts 'Found fragment with bogous length'
        raise EAPFragParseError
      end
      cur_ptr += 4
    end
    if (flags & EAPPacket::TLSFlags::MOREFRAGMENTS) != 0 then
      more_fragments = true
    end
    data += frag.type_data[cur_ptr..-1]
    if more_fragments then
      reply = eap.shift
      if reply.type != eap_type then
        $stderr.puts 'Reply packet had different type'
        raise EAPFragParseError
      end
      if (reply.type_data[0] & ( EAPPacket::TLSFlags::LENGTHINCLUDED | EAPPacket::TLSFlags::MOREFRAGMENTS | EAPPacket::TLSFlags::START )) != 0 || reply.length != 6 then
        $stderr.puts 'EAP-TLS fragment with MoreFragments set was not acked.'
        return
      end
    end
  end while more_fragments
  data
end

pktbuf = []
pktbuf.extend(MonitorMixin)
empty_cond = pktbuf.new_cond

ElasticHelper.initialize_elasticdata

Thread.start do
  loop do
    ElasticHelper.elasticdata.synchronize do
      ElasticHelper.waitcond.wait_while { ElasticHelper.elasticdata.empty? }
      toins = ElasticHelper.elasticdata.shift
      insert_into_elastic(toins)
    end
  end
end

Thread.start do
  loop do
    pktbuf.synchronize do
      empty_cond.wait_while { pktbuf.empty? }
      p = pktbuf.shift
      pkt = Packet.parse p
      # Skip all packets other then ip
      next unless pkt.is_ip?
      # Skip all fragmented ip addresses
      next if pkt.ip_frag & 0x2000 != 0
      # only look on copied packets
      next if ([pkt.ip_daddr, pkt.ip_saddr] & @config[:ipaddrs]).empty?
      # Skip non-udp packets
      next unless pkt.is_udp?
      # Skip packets for other port then radius
      next unless [pkt.udp_sport, pkt.udp_dport].include? 1812

      # Print out debug info, just for now to monitor progress
      packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      #puts "%-15s -> %-15s %-4d %s" % packet_info

      begin
        # Parse Radius packets
        rp = RadiusPacket.new(pkt)
        #puts rp.inspect
        #binding.irb
        insert_in_packetflow(rp)
      rescue PacketLengthNotValidError => e
        ##################################################
        # THIS IS A CASE THAT SHOULDN'T OCCUR.           #
        # IT SHOULD BE CATCHED BY THE FRAGMENT STATEMENT #
        ##################################################
        # TODO: Remove irb binding
        $stderr.puts e.message
        #binding.irb
      rescue => e
        # This is here for debugging.
        # TODO: remove irb binding
        puts e.inspect
        puts e.backtrace.join "\n"
        binding.irb
      end
    end
  end
end

#pcap_file = PacketFu::PcapNG::File.new
#pcap_array = pcap_file.file_to_array(filename: './debugcapture2.pcapng')
#pcap_id = 0
#pcap_array.each do |p|

iface = PacketFu::Utils.default_int
cap = Capture.new(:iface => iface, :start => true, :filter => 'port 1812')
cap.stream.each do |p|
#  pcap_id += 1
#  puts "Packet #{pcap_id}"
   pktbuf.synchronize do
     pktbuf.push p
     empty_cond.signal
   end
end

pktbufempty = false
until pktbufempty do
  pktbuf.synchronize do
    pktbufempty = pktbuf.empty?
  end
  sleep 1
end

elasticempty = false
until elasticempty do
  ElasticHelper.elasticdata.synchronize do
    elasticempty = ElasticHelper.elasticdata.empty?
  end
  sleep 1
end
