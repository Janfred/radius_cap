Thread.start do
  Thread.current.name = "Packet Matcher (RADSEC)"
  loop do
    pkt = nil
    BlackBoard.pktbuf.synchronize do
      BlackBoard.pktbuf_empty.wait_while { BlackBoard.pktbuf.empty? }

      pkt = BlackBoard.pktbuf.shift
    end

    rp = nil

    begin
      # Parse Radius packets
      rp = RadiusPacket.new(pkt[:pkt].unpack('C*'))
      rp.check_policies
    rescue PacketLengthNotValidError => e
      puts "PacketLengthNotValidError"
      puts e.message
      puts e.backtrace.join "\n"
      StatHandler.increase :packet_errored
      next
    rescue ProtocolViolationError => e
      BlackBoard.policy_logger.debug e.class.to_s + ' ' + e.message + ' From: ' + pkt[:from].inspect + ' To: ' + pkt[:to].inspect + ' Realm: ' + (rp.realm || "")
    rescue PolicyViolationError => e
      BlackBoard.policy_logger.debug e.class.to_s + ' ' + e.message + ' From: ' + pkt[:from].inspect + ' To: ' + pkt[:to].inspect + ' Realm: ' + (rp.realm || "")
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
      RadsecStreamHelper.add_packet(rp, pkt[:request], [pkt[:from], pkt[:from_sock], pkt[:source]], [pkt[:to], pkt[:to_sock], pkt[:source]])
      StatHandler.increase :packet_analyzed
    rescue PacketFlowInsertionError => e
      BlackBoard.logger.debug 'PacketFlowInsertionError: ' + e.message
      StatHandler.increase :packet_errored
    rescue => e
      puts "Error in Packetflow!"
      puts e.message
      puts e.backtrace.join "\n"
      StatHandler.increase :packet_errored
    end
  rescue => e
    $stderr.puts "ERROR IN PACKET MATCHER"
    $stderr.puts e.class.to_s + " -> " + e.message
    $stderr.puts e.backtrace.join "\n"
    BlackBoard.logger.error 'Packet Matcher errored.', e
  end
end
