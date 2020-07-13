require 'singleton'

class RadsecStream
  include SemanticLogger::Loggable

  attr_reader :time_created, :last_updated, :current_state, :current_pktid, :client, :server, :packets

  @time_created
  @last_updated
  @current_state
  @current_pktid
  @client
  @server
  @last_from_server
  @packets
  @username
  @callingstationid

  def initialize(pkt,client,server)
    @time_created = Time.now
    @last_updated = Time.now
    @current_pktid = pkt.identifier
    @current_state = pkt.state
    @last_from_server = false
    @packets = [pkt]
    @client = client
    @server = server
    @username = nil
    username_attrs = pkt.attributes.select{ |x| x[:type] == RadiusPacket::Attribute::USERNAME}
    if username_attrs.length > 0
      @username = username_attrs.first[:data]
    end
    @callingstationid = nil
    callingstationid_attrs = pkt.attributes.select{ |x| x[:type] == RadiusPacket::Attribute::CALLINGSTATIONID}
    if callingstationid_attrs.length > 0
      @callingstationid = callingstationid_attrs.first[:data]
    end

    logger.trace "Created RadsecStream for Username #{@username} MAC #{@callingstationid} from #{@client} to #{@server} and pktid #{@current_pktid}"
  end

  def add_request(pkt)
    logger.trace("Add Request packet")
    raise PacketFlowInsertionError.new("Attempted to insert a request without previous answer from server") unless @last_from_server
    raise PacketFlowInsertionError.new("Attempted to insert a request with a non matching state") if pkt.state != @current_state

    @last_from_server = false
    @current_pktid = pkt.identifier
    @last_updated = Time.now
    @packets << pkt
    nil
  end
  def add_response(pkt)
    logger.trace("Add response packet")
    raise PacketFlowInsertionError.new("Attempted to insert a response without previous request from client") if @last_from_server
    raise PacketFlowInsertionError.new("Attempted to insert a response with not matching identifier") if pkt.identifier != @current_pktid

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

class RadsecStreamHelper
  include Singleton
  include SemanticLogger::Loggable

  attr_reader :known_streams
  @known_streams

  attr_writer :timeout
  @timeout

  @housekeeping_counter

  # Initialize the known stream and set timeout
  # @param timeout [Integer] number of seconds after a Radsec Stream is considered timed out. Defaults to 60
  def initialize(timeout=60)
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

  def insert_request(pkt, client, server)
    logger.trace("Inserting packet from client")
    if pkt.state.nil?
      # This is probably a completely new request
      logger.trace("Creating a new RadsecStream")
      @known_streams << RadsecStream.new(pkt, client, server)
    else
      p = @known_streams.select { |x|
        x.current_state == pkt.state &&
        x.client == client &&
        x.server == server
      }
      if p.empty?
        logger.warn "Could not find EAP State 0x#{pkt.state.pack('C*').unpack('H*').first}"
        return
      elsif p.length > 1
        logger.warn "Found multiple EAP States for 0x#{pkt.state.pack('C*').unpack('H*').first}"
      end
      flow = p.first
      logger.trace "Insert Packet in RadsecStream"
      flow.add_request(pkt)
    end
  end

  def insert_response(pkt, server, client)
    logger.trace("Inserting packet from server")
    p = @known_streams.select { |x|
      x.client == client &&
      x.server == server &&
      x.current_pktid == pkt.identifier
    }

    if p.empty?
      logger.warn "Could not find a matching request from #{client} to #{server} and ID #{pkt.identifier}"
      return
    elsif p.length > 1
      logger.warn "Found multiple requests from #{client} to #{server} and ID #{pkt.identifier}"
      p.sort_by!(&:last_updated)
    end
    flow = p.last
    logger.trace("Insert Packet in RadsecStream")
    flow.add_response(pkt)
  end

  # Tidy up all timed out states
  def housekeeping
    @housekeeping_counter += 1
    return if @housekeeping_counter < 10
    logger.trace("Starting Housekeeping")
    t = Time.now
    old = @known_streams.select{ |x| (t-x.last_updated) > @timeout }
    old.each do |o|
      logger.info "Timing out 0x#{o.current_state.pack('C*').unpack('H*').first}" if o.current_state
      logger.info 'Timing out state without state variable' unless o.current_state
      @known_streams.delete o
    end
    @housekeeping_counter = 0
  end
  private :housekeeping

  # Add Packet to Packetflow
  # @param pkt [RadsecPacket] Packet to insert in the PacketFlow
  def self.add_packet(pkt, request, src, dst)
    logger.trace("Add packet to a stream")
    RadsecStreamHelper.instance.priv_add_packet(pkt, request, src, dst)
  end

  # Start Parsing of a certain Packetflow once it is done.
  # @param pktflow [RadsecStream] Stream to parse
  def self.notify_flow_done(pktflow)
    logger.trace("Notify Packetflow is done")
    RadsecStreamHelper.instance.priv_notify_flow_done(pktflow)
  end

  # Private helper method
  # @param pktflow [RadsecStream]
  # @private
  def priv_notify_flow_done(pktflow)
    @known_streams.delete(pktflow)
    StackParser.insert_into_parser(:radsec, pktflow)
  end

end
