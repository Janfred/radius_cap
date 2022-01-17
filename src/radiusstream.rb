# frozen_string_literal: true

require 'singleton'
require_relative './errors'

# Class for handling Streams of Radius Packets
# @!attribute [r] time_created
#   @return [Time] Time the RadiusStream was created
# @!attribute [r] last_updated
#   @return [Time] Timestamp of the last recorded packet. Used for timeouts.
# @!attribute [r] current_pktid
#   @return [Integer] Current Packet identifier
# @!attribute [r] current_state
#   @return [Object] current value of the state attribute
#   @todo find out what type this actually is.
# @!attribute [r] udp_src_ip
#   @return [String] IP Address of the NAS (e.g. the WiFi-Controller)
# @!attribute [r] udp_dst_ip
#   @return [String] IP Address of the RADIUS server
# @!attribute [r] udp_src_port
#   @return [Integer] UDP source port on the NAS side
# @!attribute [r] udp_dst_port
#   @return [Integer] UDP destination port on the RADIUS server side.
#     For now this will always be `1812`, but it may be configurable in future.
# @!attribute [r] packets
#   @return [Array<RadiusPacket>] Array of packets in received order
# @!attribute [r] username
#   @return [String] Value of the Username attribute
# @!attribute [r] callingstationid
#   @return [String] Value of the CallingStationID attribute
class RadiusStream
  include SemanticLogger::Loggable

  attr_reader :time_created, :last_updated, :current_pktid, :current_state,
              :udp_src_ip, :udp_dst_ip, :udp_src_port, :udp_dst_port, :packets, :username, :callingstationid

  # Indicates if the last package was sent by the server (true) or the client (false)
  @last_from_server


  # Create a new Instance of a RadiusStream
  # @param pkt [RadiusPacket] Initial packet of the stream
  def initialize(pkt)
    logger.trace("Initialize new Packet stream with udp data #{pkt.udp}")
    @time_created = Time.now
    @last_updated = Time.now
    @current_pktid = pkt.identifier
    @current_state = pkt.state
    @udp_src_ip = pkt.udp[:src][:ip]
    @udp_dst_ip = pkt.udp[:dst][:ip]
    @udp_src_port = pkt.udp[:src][:port]
    @udp_dst_port = pkt.udp[:dst][:port]
    @last_from_server = false
    @username = pkt.username
    @callingstationid = pkt.callingstationid
    @packets = [pkt]
  end

  # Add an answering packet from the radius
  # @param pkt [RadiusPacket] Packet to insert
  # @raise PacketFlowInsertionError if the given packet does not match the already captured flow
  # @todo The raised errors should have a message.
  def add_packet_from_radius(pkt)
    logger.trace('Add Packet from RADIUS-Server')
    # If the last message inserted was a message from the server, we can't insert an other message from the server,
    # because the client has to reply first. If this happens, it is very likely a resent
    # Packet because the original packet got lost.
    if @last_from_server
      StatHandler.increase :pkterror_reply_on_reply
      raise PacketFlowInsertionError
    end

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
      logger.debug('Final Answer added, notify RadiusStreamHelper')
      RadiusStreamHelper.notify_flow_done(self)
    end
  end

  # Add a Packet sent to the radius
  # @param pkt [RadiusPacket] Packet to insert
  # @raise PacketFlowInsertionError if the given packet does not match the already captured flow
  def add_packet_to_radius(pkt)
    logger.trace('Add Packet to RADIUS-Server')
    # If the last message was from the client, we can't add another packet from the client.
    # This is most likely the case if the RADIUS-Server failed to respond and the client
    # resent his message. In any case, it should not be added here.
    unless @last_from_server
      StatHandler.increase :pkterror_reply_on_reply
      raise PacketFlowInsertionError
    end

    # First check if the identifier is increasing
    # TODO This check is kind of complicated,
    #  because the identifier range is only 8bit and overflows on regular bases
    # raise PacketFlowInsertionError if pkt.identifier <= @current_pktid

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
# @!attribute [r] known_steams
#   @return [Array<RadiusStream>] Currently known streams
# @!attribute [rw] timeout
#   @return [Integer] Number of seconds after a Radius Stream is considered timed out.
class RadiusStreamHelper
  include Singleton
  include SemanticLogger::Loggable

  attr_reader :known_streams
  attr_accessor :timeout

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
    logger.trace('Try to insert Packet to RADIUS')

    p = @known_streams.select { |x|
      x.current_state == pkt.state &&
        x.udp_src_ip == pkt.udp[:src][:ip] &&
        x.udp_src_port == pkt.udp[:src][:port] &&
        x.udp_dst_ip == pkt.udp[:dst][:ip] &&
        x.udp_dst_port == pkt.udp[:dst][:port] &&
        x.username == pkt.username &&
        x.callingstationid == pkt.callingstationid
    }
    if p.empty?
      # This is probably a completely new request
      logger.trace('Creating a new RadiusStream')
      @known_streams << RadiusStream.new(pkt)
      return
    elsif p.length > 1
      StatHandler.increase :pkterror_multiple_state
      logger.warn "Found multiple Streams for State #{pkt.state.pack('C*').unpack('H*')}" unless pkt.state.nil?
    end

    flow = p.first
    logger.trace('Insert Packet in RadiusStream')
    flow.add_packet_to_radius(pkt)
  end

  # Private helper to insert a packet sent from the radius
  # @param pkt [RadiusPacket] Packet to insert
  # @todo There might be some packets without a state set. This should be worth a log message.
  def insert_packet_from_radius(pkt)
    logger.trace('Try to insert packet from RADIUS')
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
      logger.warn "Could not find a matching request from #{pkt.udp[:dst][:ip]}:#{pkt.udp[:dst][:port]}" \
                  " and ID #{pkt.identifier}"
      StatHandler.increase :pkterror_no_state_found
      return
    elsif p.length > 1
      # Tis case should also not occur. This means that an essential part of the RADIUS-Protocol
      # has been violated. The packet identifier should be unique given the IP Address and UDP Port
      # This is worth a warning. We can still insert it into the packet stream, but should insert it
      # into the stream which was last updated, so we should make sure the list is sorted.
      logger.warn "Found multiple requests from #{pkt.udp[:dst][:ip]}:#{pkt.udp[:dst][:port]} and ID #{pkt.identifier}"
      StatHandler.increase :pkterror_multiple_requests
      p.sort_by!(&:last_updated)
    end
    flow = p.last
    logger.trace('Insert Packet in RadiusStream')
    flow.add_packet_from_radius(pkt)
  end

  # Tidy up all timed out states
  def housekeeping
    @housekeeping_counter += 1
    return if @housekeeping_counter < 10

    logger.trace('Starting Housekeeping')
    t = Time.now
    old = @known_streams.select{ |x| (t-x.last_updated) > @timeout }
    old.each do |o|
      logger.debug "Timing out 0x#{o.current_state.pack('C*').unpack1('H*')}" if o.current_state
      logger.debug 'Timing out state without state variable' unless o.current_state
      StatHandler.increase :streams_timed_out
      StatHandler.increase :packet_timed_out, o.packets.length
      @known_streams.delete o
    end
    @housekeeping_counter = 0
  end
  private :housekeeping

  # Add Packet to Packetflow
  # @param pkt [RadiusPacket] Packet to insert in the PacketFlow
  def self.add_packet(pkt)
    logger.trace('Add packet to a Stream')
    RadiusStreamHelper.instance.priv_add_packet(pkt)
  end

  # Start Parsing of a certain Packetflow once it is done.
  # @param pktflow [RadiusStream] Stream to parse
  def self.notify_flow_done(pktflow)
    logger.trace('One Packetflow is done')
    RadiusStreamHelper.instance.priv_notify_flow_done(pktflow)
  end

  # Private helper method
  # @param pktflow [RadiusStream]
  # @private
  def priv_notify_flow_done(pktflow)
    @known_streams.delete(pktflow)
    StackParser.insert_into_parser(:radius, pktflow)
  end

end
