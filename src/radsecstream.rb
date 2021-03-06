# frozen_string_literal: true

require 'singleton'

# Class for handling Streams of Radsec Packets
# @!attribute [r] time_created
#   @return [Time] Time the RadiusStream was created
# @!attribute [r] last_updated
#   @return [Time] Timestamp of the last recorded packet. Used for timeouts.
# @!attribute [r] current_pktid
#   @return [Integer] Current Packet identifier
# @!attribute [r] current_state
#   @return [Object] current value of the state attribute
#   @todo find out what type this actually is.
# @!attribute [r] packets
#   @return [Array<RadiusPacket>] Array of packets in received order
# @!attribute [r] username
#   @return [String] Value of the Username attribute
# @!attribute [r] callingstationid
#   @return [String] Value of the CallingStationID attribute
# @!attribute [r] client
#   @return [Object] Information about the requesting client
# @!attribute [r] server
#   @return [Object] Information about the server
class RadsecStream
  include SemanticLogger::Loggable

  attr_reader :time_created, :last_updated, :current_state, :current_pktid,
              :client, :server,
              :packets, :username, :callingstationid

  @last_from_server

  def initialize(pkt, client, server)
    @time_created = Time.now
    @last_updated = Time.now
    @current_pktid = pkt.identifier
    @current_state = pkt.state
    @last_from_server = false
    @packets = [pkt]
    @client = client
    @server = server
    @username = pkt.username
    @callingstationid = pkt.callingstationid

    logger.trace "Created RadsecStream for Username #{@username} MAC #{@callingstationid}" \
                 " from #{@client} to #{@server} and pktid #{@current_pktid}"
  end

  # Add Request to the Stream
  # @param [RadiusPacket] pkt RADIUS request to add
  # @raise PacketFlowInsertionError
  def add_request(pkt)
    logger.trace('Add Request packet')
    unless @last_from_server
      StatHandler.increase :pkterror_reply_on_reply
      raise PacketFlowInsertionError, 'Attempted to insert a request without previous answer from server'
    end

    unless pkt.state == @current_state
      raise PacketFlowInsertionError, 'Attempted to insert a request with a non matching state'
    end

    @last_from_server = false
    @current_pktid = pkt.identifier
    @last_updated = Time.now
    @packets << pkt
    nil
  end

  # Adds Response to the Stream
  # @param [RadiusPacket] pkt RADIUS response to add
  # @raise PacketFlowInsertionError
  def add_response(pkt)
    logger.trace('Add response packet')
    if @last_from_server
      StatHandler.increase :pkterror_reply_on_reply
      raise PacketFlowInsertionError, 'Attempted to insert a response without previous request from client'
    end
    unless pkt.identifier == @current_pktid
      raise PacketFlowInsertionError, 'Attempted to insert a response with not matching identifier'
    end

    @last_from_server = true
    @current_state = pkt.state
    @last_updated = Time.now
    @packets << pkt

    if pkt.packettype == RadiusPacket::Type::ACCEPT || pkt.packettype == RadiusPacket::Type::REJECT
      logger.debug 'Final answer added, notify RadsecStreamHelper'
      RadsecStreamHelper.notify_flow_done(self)
    end
  end
end

# Helper Class for inserting Data into the Radsec Streams
# @!attribute [r] known_streams
#   @return [Array<RadiusStream>] Currently known streams
# @!attribute [rw] timeout
#   @return [Integer] Number of seconds after a Steam is considered timed out.
class RadsecStreamHelper
  include Singleton
  include SemanticLogger::Loggable

  attr_reader :known_streams
  attr_accessor :timeout

  @housekeeping_counter

  # Initialize the known stream and set timeout
  # @param timeout [Integer] number of seconds after a Radsec Stream is considered timed out. Defaults to 60
  def initialize(timeout = 10)
    logger.trace("Initialize RadsecStreamHelper with timeout of #{timeout} seconds")
    @known_streams = []
    @timeout = timeout
    @housekeeping_counter = 0
  end

  # Private helper to add packet in Packetflow.
  # This function is used internally and should never be called directly.
  # @private
  def priv_add_packet(pkt, request, src, dst)
    if request
      insert_request(pkt, src, dst)
    else
      insert_response(pkt, src, dst)
    end
    # After we inserted the packet we can do housecleaning.
    housekeeping
  end

  # Insert a request in a PacketFlow
  # @param pkt [RadiusPacket] Packet to insert
  # @param client sending client of the request
  # @param server receiving server of the request
  def insert_request(pkt, client, server)
    logger.trace('Inserting packet from client')
    p = @known_streams.select do |x|
      x.current_state == pkt.state &&
        x.client == client &&
        x.server == server &&
        x.username == pkt.username &&
        x.callingstationid == pkt.callingstationid
    end
    if p.empty?
      logger.trace 'Creating a new RadsecStream'
      @known_streams << RadsecStream.new(pkt, client, server)
      return
    elsif p.length > 1
      if pkt.state.nil?
        logger.warn 'Found multiple EAP States for nil state'
        StatHandler.increase :pkterror_multiple_state
      else
        StatHandler.increase :pkterror_multiple_state
        logger.warn "Found multiple EAP States for 0x#{pkt.state.pack('C*').unpack1('H*')}"
      end
    end
    flow = p.first
    logger.trace 'Insert Packet in RadsecStream'
    flow.add_request(pkt)
  end

  # Insert a response in a PacketFlow
  # @param pkt [RadiusPacket] Packet to insert
  # @param server sending server of the response
  # @param client receiving client of the response
  def insert_response(pkt, server, client)
    logger.trace('Inserting packet from server')
    p = @known_streams.select do |x|
      x.current_pktid == pkt.identifier &&
        x.client == client &&
        x.server == server
    end

    if p.empty?
      logger.debug "Could not find a matching request from #{client} to #{server} and ID #{pkt.identifier}"
      StatHandler.increase :pkterror_no_state_found
      return
    elsif p.length > 1
      logger.debug "Found multiple requests from #{client} to #{server} and ID #{pkt.identifier}"
      StatHandler.increase :pkterror_multiple_requests
      p.sort_by!(&:last_updated)
    end
    flow = p.last
    logger.trace('Insert Packet in RadsecStream')
    flow.add_response(pkt)
  end

  # Tidy up all timed out states
  def housekeeping
    @housekeeping_counter += 1
    return if @housekeeping_counter < 10

    logger.trace('Starting Housekeeping')
    t = Time.now
    old = @known_streams.select { |x| (t - x.last_updated) > @timeout }
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
  # @param pkt [RadsecPacket] Packet to insert in the PacketFlow
  def self.add_packet(pkt, request, src, dst)
    logger.trace('Add packet to a stream')
    RadsecStreamHelper.instance.priv_add_packet(pkt, request, src, dst)
  end

  # Start Parsing of a certain Packetflow once it is done.
  # @param pktflow [RadsecStream] Stream to parse
  def self.notify_flow_done(pktflow)
    logger.trace('Notify Packetflow is done')
    RadsecStreamHelper.instance.priv_notify_flow_done(pktflow)
  end

  # Private helper method
  # @param pktflow [RadsecStream]
  # @private
  def priv_notify_flow_done(pktflow)
    @known_streams.delete(pktflow)
    StackParser.insert_into_parser(:radsec, pktflow)
    StatHandler.increase :streams_analyzed
  end

end
