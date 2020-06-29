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

  def initialize(pkt,client,server)
    @time_created = Time.now
    @last_updated = Time.now
    @current_pktid = pkt.identifier
    @current_state = pkt.state
    @last_from_server = false
    @packets = [pkt]
  end

  def add_request(pkt)
    # TODO
  end
  def add_response(pkt)
    # TODO
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

  def initialize(timeout=60)
    logger.trace("Initialize RadsecStreamHelper with timeout of #{timeout} seconds")
    @known_streams = []
    @timeout = timeout
    @housekeeping_counter = 0
  end

  def insert_request(pkt, client, server)
    logger.trace("Inserting packet from client")
    if pkt.state.nil?
      # This is probably a completely new request
      logger.trace("Creating a new RadsecStream")
      @known_streams << RadsecStream.new(pkt, client, server)
    else
      p = @known_streams.select {|x| x.current_state == pkt.state }
      if p.empty?
        logger.warn "Could not find EAP State 0x#{pkt.state.pack('C*').unpack('H*').first}"
        return
      else p.length > 1
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
      x.src_client == server &&
      x.dst_client == client &&
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

  def priv_add_packet(pkt, request, src, dst)
    if request
      insert_request(pkt, src, dst)
    else
      insert_response(pkt, src, dst)
    end
  end

  def self.add_packet(pkt, request, src, dst)
    logger.trace("Add packet to a stream")
    RadsecStreamHelper.instance.priv_add_packet(pkt, request, src, dst)
  end

  def self.notify_flow_done(pktflow)
    logger.trace("Notify Packetflow is done")
    RadsecStream.instance.priv_notify_flow_done(pktflow)
  end

  def priv_notify_flow_done(pktflow)
    @known_streams.delete(pktflow)
    StackParser.insert_into_parser(:radsec, pktflow)
  end
end