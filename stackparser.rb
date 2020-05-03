# Class for parsing Streams
class StackParser

  include SemanticLogger::Loggable
  include Singleton

  # [Array<Hash>] Data to parse. Saved in format type: <symbol>, data: Data
  # @private
  attr_reader :priv_stack_data
  @priv_stack_data

  # Wait Condition for synchronizing
  # @private
  attr_reader :priv_waitcond
  @priv_waitcond

  # Parser Thread
  attr_reader :parsethread
  @parsethread

  def initialize
    @priv_stack_data = []
    @priv_stack_data.extend(MonitorMixin)
    @priv_waitcond = @priv_stack_data.new_cond
    @parsethread = Thread.start do
      parser
    end
  end

  # Insert a new Packet to the Parser's Queue
  # @param type [Symbol] The Type of the inserted data. May be one of
  #  :radius, :eap or :eap_tls
  # @param data Object containing the Data.
  def self.insert_into_parser(type, data)
    instance.priv_stack_data.synchronize do
      instance.priv_stack_data << {type: type, data: data}
      instance.priv_waitcond.signal
    end

    nil
  end

  # Parser Function invoked by the Parse Thread
  def parser
    loop do
      to_parse = nil
      @priv_stack_data.synchronize do
        @priv_waitcond.wait_while { @priv_stack_data.empty? }
        to_parse = @priv_stack_data.shift
      end
      if to_parse.nil?
        logger.error "Parser found a nil to parse. That seems not right."
        next
      end
      ProtocolStack.new to_parse
    end
  end

  private :parser
end

class ProtocolStackError < StandardError
end

# ProtocolStack for Parsing all Layers
# @!attribute [r] radius_stream
#   @return [RadiusStream] Radius Stream
# @!attribute [r] radius_data
#   @return [Hash] Radius Data
# @!attribute [r] eap_stream
#   @return [EAPStream] EAP Stream
# @!attribute [r] eap_data
#   @return [Hash] EAP Data
# @!attribute [r] eap_tls_stream
#   @return [EAPTLSStream] EAP TLS Stream
# @!attribute [r] eap_tls_data
#   @return [Hash] EAP-TLS Data
class ProtocolStack

  attr_reader :radius_data, :radius_stream, :eap_data, :eap_stream, :eap_tls_data, :eap_tls_stream, :tls_data

  def initialize(to_parse)
    initialize_variables

    case to_parse[:type]
    when :radius
      # RADIUS Packets
      check_passed_type(RadiusStream, to_parse[:data].class)
      @radius_stream = to_parse[:data]
      parse_from_radius
    when :eap
      # EAP Packets
      check_passed_type(EAPStream, to_parse[:data].class)
      @eap_stream = to_parse[:data]
      parse_from_eap
    when :eap_tls
      # EAP-TLS Packets
      check_passed_type(EAPTLSStream, to_parse[:data].class)
      @eap_tls_stream = to_parse[:data]
      parse_from_eaptls
    else
      # Something weird here.
      logger.warn "Seen unknown type #{to_parse[:type]}. Doing nothing."
    end
  end

  # Generate Hash to insert into Elasticsearch
  def to_h

  end

  private

  # Helper Method to check if the passed class is the expected class
  # @raise ProtocolStackError
  def check_passed_type(expected_klass, actual_klass)
    return if expected_klass == actual_klass
    raise ProtocolStackError.new "The actual type of the Stream (#{actual_klass.to_s}) does not match expected (#{expected_klass.to_s})"
  end

  # Parse from the RADIUS Layer upwards
  def parse_from_radius

    raise ProtocolStackError.new "The RADIUS Stream can not be empty!" if @radius_stream.nil?
    raise ProtocolStackError.new "The RADIUS Stream is not an RadiusStream Object" unless @radius_stream.is_a? RadiusStream
    raise ProtocolStackError.new "The RadiusStream seems to be empty!" if @radius_stream.packets.length == 0
    # First we extract Metadata and Attributes from the RADIUS Stream
    @radius_data[:information] = {}
    @radius_data[:information][:roundtrips] = @radius_stream.packets.length
    @radius_data[:information][:time] = @radius_stream.last_updated - @radius_stream.time_created
    @radius_data[:information][:max_server_pkt_size] = 0
    @radius_data[:information][:max_client_pkt_size] = 0
    @radius_data[:information][:total_server_pkt_size] = 0
    @radius_data[:information][:total_client_pkt_size] = 0

    lastpkt = @radius_stream.packets.last
    # Error Message intentionally left blank, because this should not happen.
    raise ProtocolStackError if lastpkt.nil?
    raise ProtocolStackError unless lastpkt.is_a? RadiusPacket
    @radius_data[:information][:accept] = lastpkt.packettype == RadiusPacket::Type::ACCEPT

    is_client_pkt = true
    @radius_stream.packets.each do |pkt|
      total = :total_server_pkt_size
      max_c = :max_server_pkt_size
      if is_client_pkt
        total = :total_client_pkt_size
        max_c = :max_client_pkt_size
      end
      size = pkt.raw_data.length
      @radius_data[:information][total] += size
      @radius_data[:information][max_c] = size if @radius_data[:information][max_c] < size
      is_client_pkt = !is_client_pkt
    end
    @radius_data[:attributes] = {}
    firstpkt = @radius_stream.packets.first

    raise ProtocolStackError if firstpkt.nil?

    username_a = firstpkt.attributes.select { |x| x[:type] == RadiusPacket::Attribute::USERNAME }
    raise ProtocolStackError.new "The First Radius Packet did not not contain exactly one Username attribute" if username_a.length != 1
    @radius_data[:attributes][:username] = username_a.first[:data].pack('C*')

    mac_a = firstpkt.attributes.select { |x| x[:type] == RadiusPacket::Attribute::CALLINGSTATIONID }
    if mac_a.length != 1
      logger.warn "Seen a Radius Stream with not exactly one Calling Station ID Attribute"
    end
    if mac_a.length == 0
      @radius_data[:attributes][:mac] = "ff:ff:ff:ff:ff:ff"
    else
      @radius_data[:attributes][:mac] = mac_a.first[:data].pack('C*')
    end
    normalize_mac!

    # Now we can parse the EAP Content of the Packets
    @eap_stream = EAPStream.new(@radius_stream)
    parse_from_eap
  end

  # Normalize the MAC Address saved in @radius_data[:attributes][:mac]
  def normalize_mac!
    raise ProtocolStackError.new "MAC Address is not available!" if @radius_data[:attributes][:mac].nil?
    @radius_data[:attributes][:mac].downcase!
    m_d = @radius_data[:attributes][:mac].match /^([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2})$/
    if m_d && m_d.length == 7
      @radius_data[:attributes][:mac] = m_d[1, 6].join ":"
    else
      logger.warn "Found bad formatted or invalid MAC-Address: #{@radius_data[:attributes][:mac]} Falling back to default."
      @radius_data[:attributes][:mac] = "ff:ff:ff:ff:ff:ff"
    end
  end

  # Parse from the EAP Layer upwards
  def parse_from_eap

    raise ProtocolStackError.new "The EAP Stream must not be empty" if @eap_stream.nil?
    raise ProtocolStackError.new "The EAP Stream ist not an EAPStream Object" unless @eap_stream.is_a? EAPStream
    # First Parse EAP Metadata
    @eap_data[:information] = {}
    @eap_data[:information][:initial_eaptype] = @eap_stream.initial_eap_type
    @eap_data[:information][:wanted_eaptype] = @eap_stream.wanted_eap_type
    @eap_data[:information][:actual_eaptype] = @eap_stream.eap_type
    @eap_data[:information][:roundtrips] = @eap_stream.eap_packets.length

    # Here is now decided how to proceed with the packet.
    case @eap_stream.eap_type
    when nil
      # This EAP Stream contains most likely a failed agreement between Client and server
      logger.info "Seen Failed EAP Communication."
    when EAPPacket::Type::TTLS,
        EAPPacket::Type::PEAP,
        EAPPacket::Type::TLS
      logger.info 'Found an EAP-TLS based EAP Type'
      @eap_tls_stream = EAPTLSStream.new(@eap_stream.eap_packets[@eap_stream.first_eap_payload..-1])
    when EAPPacket::Type::EAPPWD
      logger.info 'Found EAP-PWD Communication'
    when EAPPacket::Type::MD5CHALLENGE
      logger.info 'Found MD5CHALLENGE Communication'
    when EAPPacket::Type::MSEAP
      logger.info 'Found MSEAP Communication'
    else
      logger.warn "Unknown EAP Type #{@eap_stream.eap_type}"
    end
  end

  # Parse from the EAP-TLS Layer upwards
  def parse_from_eaptls

  end

  # Initialize all class variables
  def initialize_variables
    @radius_data = {}
    @radius_stream = nil
    @eap_data = {}
    @eap_stream = nil
    @eap_tls_data = {}
    @eap_tls_stream = nil
    @tls_data = {}
  end
end