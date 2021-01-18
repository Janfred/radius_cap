Thread.start do
  Thread.current.name = "Packet Matcher (PCAP)"
  loop do
    p = nil
    BlackBoard.pktbuf.synchronize do
      BlackBoard.pktbuf_empty.wait_while { BlackBoard.pktbuf.empty? }
      p = BlackBoard.pktbuf.shift
    end

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
      puts "PacketLengthNotValidError"
      puts e.message
      puts e.backtrace.join "\n"
      StatHandler.increase :packet_errored
      next
    rescue ProtocolViolationError => e
      BlackBoard.policy_logger.info e.class.to_s + ' ' + e.message + ' From: ' + pkt.ip_saddr + ' To: ' + pkt.ip_daddr + ' Realm: ' + (pkt.realm || "")
    rescue PolicyViolationError => e
      BlackBoard.policy_logger.info e.class.to_s + ' ' + e.message + ' From: ' + pkt.ip_saddr + ' To: ' + pkt.ip_daddr + ' Realm: ' + (pkt.realm || "")
    rescue => e
      puts "General error in Parsing!"
      puts e.message
      puts e.backtrace.join "\n"
      puts p.unpack("H*").first
      StatHandler.increase :packet_errored
      next
    end

    next if rp.nil?

    begin
      RadiusStreamHelper.add_packet(rp)
      StatHandler.increase :packet_analyzed
    rescue PacketFlowInsertionError => e
      BlackBoard.logger.warn 'PacketFlowInsertionError: ' + e.message
      StatHandler.increase :packet_errored
    rescue => e
      puts "Error in Packetflow!"
      puts e.message
      puts e.backtrace.join "\n"
      StatHandler.increase :packet_errored
    end
  end
end
