
require 'singleton'

class PacketFlowInsertionError < StandardError
end

class RadiusStream
  include SemanticLogger::Loggable

  attr_reader :last_updated, :current_pktid, :current_state, :udp_src_ip, :udp_dst_ip, :udp_src_port, :udp_dst_port, :packets
  # Timestamp of the last update of this specific stream. Used for timeouts.
  @last_updated
  # Current value of the State Attribute
  @current_state
  # Current Radius Identifier
  @current_pktid
  # IP Address of the NAS (e.g. the WiFi-Controller)
  @udp_src_ip
  # IP Address of the RADIUS Server
  @udp_dst_ip
  # UDP Source Port at the NAS (e.g. WiFi-Controller)
  @udp_src_port
  # UDP Destination Port at the RADIUS Server.
  # @todo Currently this will always be `1812` but maybe this should be configurable.
  @udp_dst_port
  # Indicates if the last package was sent by the server (true) or the client (false)
  @last_from_server
  # [Array<RadiusPacket>] Array of packets (RadiusPacket) in received order
  @packets

  # Create a new Instance of a RadiusStream
  # @param pkt [RadiusPacket] Initial packet of the stream
  def initialize(pkt)
    logger.trace("Initialize new Packet stream with udp data #{pkt.udp}")
    @last_updated = Time.now
    @current_pktid = pkt.identifier
    @current_state = pkt.state
    @udp_src_ip = pkt.udp[:src][:ip]
    @udp_dst_ip = pkt.udp[:dst][:ip]
    @udp_src_port = pkt.udp[:src][:port]
    @udp_dst_port = pkt.udp[:dst][:port]
    @last_from_server = false
    @packets = [pkt]
  end

  # Add an answering packet from the radius
  # @param pkt [RadiusPacket] Packet to insert
  # @raise PacketFlowInsertionError if the given packet does not match the already captured flow
  # @todo The raised errors should have a message.
  def add_packet_from_radius(pkt)
    logger.trace("Add Packet from RADIUS-Server")
    # If the last message inserted was a message from the server, we can't insert an other message from the server,
    # because the client has to reply first. If this happens, it is very likely a resent
    # Packet because the original packet got lost.
    raise PacketFlowInsertionError if @last_from_server

    # First check if the identifier matches the current identifier
    # RADIUS, being a transactional protocol, always has a Request-Response structure.
    raise PacketFlowInsertionError if pkt.identifier != @current_pktid

    # Then check for the IP Addresses and UDP Ports
    # Because this is an answer from the server source and destination are swapped
    port_helper(pkt.udp[:dst], pkt.udp[:src])

    # Once the checks are completed, we can insert the packet in the current flow and update
    @last_from_server = true
    @current_state = pkt.state
    @last_updated = Time.now
    @packets << pkt

    # If this was a final answer (Accept or Reject) we have to tell our supervisor that our
    # flow is now complete and can be parsed.
    if pkt.packettype == RadiusPacket::Type::ACCEPT ||
        pkt.packettype == RadiusPacket::Type::REJECT
      logger.debug("Final Answer added, notify RadiusStreamHelper")
      RadiusStreamHelper.notify_flow_done(self)
    end
  end

  # Add a Packet sent to the radius
  # @param pkt [RadiusPacket] Packet to insert
  # @raise PacketFlowInsertionError if the given packet does not match the already captured flow
  def add_packet_to_radius(pkt)
    logger.trace("Add Packet to RADIUS-Server")
    # If the last message was from the client, we can't add another packet from the client.
    # This is most likely the case if the RADIUS-Server failed to respond and the client
    # resent his message. In any case, it should not be added here.
    raise PacketFlowInsertionError unless @last_from_server

    # First check if the identifier is increasing
    # TODO This check is kind of complicated,
    #  because the identifier range is only 8bit and overflows on regular bases
    #raise PacketFlowInsertionError if pkt.identifier <= @current_pktid

    # The state attribute must be the same as sent by the server. If it was omitted (nil)
    # then it must not be included in the client's answer
    raise PacketFlowInsertionError if pkt.state != @current_state

    # Then we check for the IP Addresses and UDP Ports
    port_helper(pkt.udp[:src], pkt.udp[:dst])

    # Once the checks are completed, we can add the packet and update our state
    @current_pktid = pkt.identifier
    @last_from_server = false
    @last_updated = Time.now
    @packets << pkt
    nil
  end

  def port_helper(src,dst)
    raise PacketFlowInsertionError if src[:ip] != @udp_src_ip
    raise PacketFlowInsertionError if dst[:ip] != @udp_dst_ip

    raise PacketFlowInsertionError if src[:port] != @udp_src_port
    raise PacketFlowInsertionError if dst[:port] != @udp_dst_port
  end
  private :port_helper
end

# Helper Class for inserting Data into the RadiusSteams
class RadiusStreamHelper
  include Singleton
  include SemanticLogger::Loggable

  # [Array<RadiusStream>] Currently known streams
  attr_reader :known_streams
  @known_streams

  # [Integer] Number of seconds after a Radius Stream is considered timed out.
  attr_writer :timeout
  @timeout

  # Counter for housekeeping calls. The Housekeeping is only executed every 10 packets.
  @housekeeping_counter

  # Initialize the known stream and set timeout
  # @param timeout [Integer] number of seconds after a Radius Stream is considered timed out. Defaults to 60
  def initialize(timeout = 60)
    logger.trace("Initialize RadiusStreamHelper with timeout of #{timeout} seconds")
    @known_streams = []
    @timeout = timeout
    @housekeeping_counter = 0
  end

  # Private helper to add packet in Packetflow.
  # This function is used internally and should never be called directly.
  # @private
  def priv_add_packet(pkt)
    if pkt.udp[:dst][:port] == 1812
      insert_packet_to_radius(pkt)
    else
      insert_packet_from_radius(pkt)
    end
    # After we inserted the packet we can do housecleaning.
    housekeeping
  end

  # Private helper to insert a packet sent to the radius
  def insert_packet_to_radius(pkt)
    logger.trace("Try to insert Packet to RADIUS")
    if pkt.state.nil?
      # This is probably a completely new request
      # TODO There are some realms (looking at you, ads.fraunhofer.de) which don't send a State attribute.
      #  So this could actually be a packet for an ongoing communication. It can be determined by matching
      #  the ip address, udp port and packet identifier (increased by one)
      #  For now we just assume it is a new stream.
      logger.trace("Creating a new RadiusStream")
      @known_streams << RadiusStream.new(pkt)
    else
      # If a State exists this is an ongoing communication
      p = @known_streams.select{ |x| x.current_state == pkt.state }
      if p.empty?
        # This is a state we haven't seen before.
        # It is very likely in the first few seconds after starting the script.
        # When it occurs afterwards it means that either a previous packet wasn't captured

        # TODO This packet should be included in the debug capture
        logger.warn "Could not find EAP State 0x#{pkt.state.pack('C*').unpack('H*').first}"
        return
      elsif p.length > 1
        # If this case occurs, we maybe captured a repeated packet. It should not happen at all.
        # Anyway, we can insert the packet in the flow.
        # The RadiusPacket class will handle the case that this actually is a resent packet.

        # TODO This packet should be included in the debug capture
        logger.warn "Found multiple EAP States for 0x#{pkt.state.pack('C*').unpack('H*').first}"
      end
      flow = p.first
      logger.trace("Insert Packet in RadiusStream")
      flow.add_packet_to_radius(pkt)
    end
  end

  # Private helper to insert a packet sent from the radius
  # @param pkt [RadiusPacket] Packet to insert
  # @todo There might be some packets without a state set. This should be worth a log message.
  def insert_packet_from_radius(pkt)
    logger.trace("Try to insert packet from RADIUS")
    # This must be an ongoing packet. Packets sent are matched by UDP Port/IP Address and Packet ID
    p = @known_streams.select { |x|
      x.udp_src_ip == pkt.udp[:dst][:ip] &&
      x.udp_dst_ip == pkt.udp[:src][:ip] &&
      x.udp_src_port == pkt.udp[:dst][:port] &&
      x.udp_dst_port == pkt.udp[:src][:port] &&
      x.current_pktid == pkt.identifier
    }

    if p.empty?
      # This case should not occur. This is probably the case if the packet, which the
      # RADIUS-Server is answering to, was not captured.
      # TODO This packet should be included in the debug capture
      logger.warn "Could not find a matching request from #{pkt.udp[:dst][:ip]}:#{pkt.udp[:dst][:port]} and ID #{pkt.identifier}"
      return
    elsif p.length > 1
      # Tis case should also not occur. This means that an essential part of the RADIUS-Protocol
      # has been violated. The packet identifier should be unique given the IP Address and UDP Port
      # This is worth a warning. We can still insert it into the packet stream, but should insert it
      # into the stream which was last updated, so we should make sure the list is sorted.
      logger.warn "Found multiple requests from #{pkt.udp[:dst][:ip]}:#{pkt.udp[:dst][:port]} and ID #{pkt.identifier}"
      p.sort_by!(&:last_updated)
    end
    flow = p.last
    logger.trace("Insert Packet in RadiusStream")
    flow.add_packet_from_radius(pkt)
  end

  # Tidy up all timed out states
  def housekeeping
    @housekeeping_counter += 1
    return if @housekeeping_counter < 10
    logger.trace("Starting Housekeeping")
    t = Time.now
    old = @known_streams.select{ |x| (t-x.last_updated) > @timeout }
    old.each do |o|
      # TODO This should become a message for the Logging
      logger.info "Timing out 0x#{o.current_state.pack('C*').unpack('H*').first}" if o.current_state
      logger.info 'Timing out state without state variable' unless o.current_state
      @known_streams.delete o
    end
    @housekeeping_counter = 0
  end
  private :housekeeping

  # Add Packet to Packetflow
  # @param pkt [RadiusPacket] Packet to insert in the PacketFlow
  def self.add_packet(pkt)
    logger.trace("Add packet to a Stream")
    RadiusStreamHelper.instance.priv_add_packet(pkt)
  end

  # Start Parsing of a certain Packetflow once it is done.
  # @param pktflow [RadiusStream] Stream to parse
  def self.notify_flow_done(pktflow)
    logger.trace("One Packetflow is done")
    RadiusStreamHelper.instance.priv_notify_flow_done(pktflow)
  end

  # Private helper method
  # @param pktflow [RadiusStream]
  # @private
  def priv_notify_flow_done(pktflow)
    @known_streams.delete(pktflow)
    # TODO Here there should be the Parsing for EAP. Maybe as a Thread?
    #  Don't know yet.
    eap_stream = EAPStream.new(pktflow)
    case eap_stream.eap_type
    when nil
      # This EAP Stream has no EAP Type. So most likely the Client and Server could not agree on an EAP-Type
    when EAPPacket::Type::TTLS,
        EAPPacket::Type::PEAP,
        EAPPacket::Type::TLS
      # This is exactly what we want. This is all EAP-TLS based, so they are all parseable by EAPTLSStream
      logger.trace("Found an EAP-TLS based EAP Type")
    when EAPPacket::Type::EAPPWD
      # This should also be interesting. Especially to see if some Servers try to use EAP-PWD with salt
      logger.info("Found EAP PWD")
    when EAPPacket::Type::MD5CHALLENGE
      # This might be worth a warning, because this should not happen.
      logger.info("Found MD5CHALLENGE")
    when EAPPacket::Type::MSEAP
      # I have no Idea what this is.
      logger.info("Found MSEAP")
    else
      logger.warn("Unknown EAP Type #{eap_stream.eap_type}")
    end
  end

end
