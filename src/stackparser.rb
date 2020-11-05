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
      Thread.current.name = "Parser"
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
      begin
        to_parse = nil
        @priv_stack_data.synchronize do
          @priv_waitcond.wait_while { @priv_stack_data.empty? }
          to_parse = @priv_stack_data.shift
        end
        if to_parse.nil?
          logger.error "Parser found a nil to parse. That seems not right."
          next
        end
        result = ProtocolStack.new to_parse

        # If the DontSave flag is set, we just skip this.
        next if result.dontsave

        to_insert_in_elastic = result.to_h
        logger.debug 'Complete Data: ' + to_insert_in_elastic.to_s

        ElasticHelper.elasticdata.synchronize do
          ElasticHelper.elasticdata.push to_insert_in_elastic
          ElasticHelper.waitcond.signal
        end
      rescue => e
        logger.error("Error in parsing", exception: e)
      end
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

  include SemanticLogger::Loggable

  attr_reader :radius_data, :radius_stream, :radsec_data, :radsec_stream, :eap_data, :eap_stream, :eap_tls_data, :eap_tls_stream, :tls_data, :dontsave

  def initialize(to_parse)
    initialize_variables

    begin
      case to_parse[:type]
      when :radius
        # RADIUS Packets
        check_passed_type(RadiusStream, to_parse[:data].class)
        @radius_stream = to_parse[:data]
        parse_from_radius
      when :radsec
        # RADSEC Packet
        check_passed_type(RadsecStream, to_parse[:data].class)
        @radsec_stream = to_parse[:data]
        parse_from_radsec
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
    rescue => e
      write_debug_capture_log
      raise e
    end
  end

  # Generate Hash to insert into Elasticsearch
  def to_h
    to_ret = {}
    to_ret[:radius] = @radius_data if @radius_data
    to_ret[:radsec] = @radsec_data if @radsec_data
    to_ret[:eap] = @eap_data if @eap_data
    to_ret[:eaptls] = @eap_tls_data if @eap_tls_data
    to_ret[:tls] = @tls_data if @tls_data

    to_ret
  end

  private

  # Write the complete RADIUS Stream to a pcap File
  def write_debug_capture_log
    if @radius_stream && @radius_stream.is_a?(RadiusStream)
      pcapng_file = PacketFu::PcapNG::File.new
      packets = []
      @radius_stream.packets.each do |pkt|
        if pkt.packetfu_pkt && pkt.packetfu_pkt.is_a?(PacketFu::Packet)
          packets << pkt.packetfu_pkt
        end
      end
      # TODO This should be disableable by configuration option
      pcap_file_name = File.join('debugcapture', 'debug_' + DateTime.now.strftime('%s') + '.pcap')
      logger.info "Saving debug capture to #{pcap_file_name}"
      pcapng_file.array_to_file(array: packets, file: pcap_file_name)
    end
  end

  # Helper Method to check if the passed class is the expected class
  # @raise ProtocolStackError
  def check_passed_type(expected_klass, actual_klass)
    return if expected_klass == actual_klass
    raise ProtocolStackError.new "The actual type of the Stream (#{actual_klass.to_s}) does not match expected (#{expected_klass.to_s})"
  end

  # Parse Packetsize
  # @param loop_var [Array] Variable with packets
  # @param start_with_client [Boolean] Sets if the first packet is a packet from the client
  # @return [Hash] Hash containing the Metadata
  # @yield [pkt] Block to determine the size of the packet
  # @yieldparam pkt Packet to parse
  # @yieldreturn [Integer] Size of the given packet
  def parse_packetsize(loop_var, start_with_client = true, &size_block)
    to_return = {}
    to_return[:max_client_pkt_size] = 0
    to_return[:max_server_pkt_size] = 0
    to_return[:total_client_pkt_size] = 0
    to_return[:total_server_pkt_size] = 0
    is_client_pkt = start_with_client
    loop_var.each do |pkt|
      total = :total_server_pkt_size
      max_s = :max_server_pkt_size
      if is_client_pkt
        total = :total_client_pkt_size
        max_s = :max_client_pkt_size
      end
      size = size_block.call(pkt)
      to_return[total] += size
      to_return[max_s] = size if to_return[max_s] < size
      is_client_pkt = !is_client_pkt
    end

    to_return
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

    @radius_data[:information].merge!(parse_packetsize(@radius_stream.packets) { |x| x.raw_data.length })

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
    normalize_mac! @radius_data

    logger.debug 'Radius Data: ' + @radius_data.to_s

    # Now we can parse the EAP Content of the Packets
    @eap_stream = EAPStream.new(@radius_stream)
    parse_from_eap
  end

  # Parse from RADSEC Layer upwards
  def parse_from_radsec
    raise ProtocolStackError.new "The RADSEC Stream can not be empty!" if @radsec_stream.nil?
    raise ProtocolStackError.new "The RADSEC Stream is not an RadsecStream Object" unless @radsec_stream.is_a? RadsecStream
    raise ProtocolStackError.new "The RadsecStream seems to be empty!" if @radsec_stream.packets.length == 0

    @radsec_data[:information] = {}
    @radsec_data[:information][:roundtrips] = @radsec_stream.packets.length
    @radsec_data[:information][:time] = @radsec_stream.last_updated - @radsec_stream.time_created
    @radsec_data[:information][:max_server_pkt_size] = 0
    @radsec_data[:information][:max_client_pkt_size] = 0
    @radsec_data[:information][:total_server_pkt_size] = 0
    @radsec_data[:information][:total_client_pkt_size] = 0

    lastpkt = @radsec_stream.packets.last

    raise ProtocolStackError if lastpkt.nil?
    raise ProtocolStackError unless lastpkt.is_a? RadiusPacket
    @radsec_data[:information][:accept] = lastpkt.packettype == RadiusPacket::Type::ACCEPT
    @radsec_data[:information].merge!(parse_packetsize(@radsec_stream.packets) {|x| x.raw_data.length })

    @radsec_data[:attributes] = {}
    firstpkt = @radsec_stream.packets.first

    raise ProtocolStackError if firstpkt.nil?

    username_a = firstpkt.attributes.select { |x| x[:type] == RadiusPacket::Attribute::USERNAME }
    raise ProtocolStackError.new "The First Radius Packet did not not contain exactly one Username attribute" if username_a.length != 1
    @radsec_data[:attributes][:username] = username_a.first[:data].pack('C*')

    mac_a = firstpkt.attributes.select { |x| x[:type] == RadiusPacket::Attribute::CALLINGSTATIONID }
    if mac_a.length != 1
      logger.warn "Seen a Radsec Stream with not exactly one Calling Station ID Attribute"
    end
    if mac_a.length == 0
      @radsec_data[:attributes][:mac] = "ff:ff:ff:ff:ff:ff"
    else
      @radsec_data[:attributes][:mac] = mac_a.first[:data].pack('C*')
    end
    normalize_mac! @radsec_data

    logger.debug 'Radsec Data: ' + @radsec_data.to_s
    # TODO Handle errors here so the log is not slammed
    begin
      @eap_stream = EAPStream.new(@radsec_stream)
      parse_from_eap
    rescue EAPStreamError => e
      logger.warn 'EAPStreamError: ' + e.message
    end
  end

  # Normalize the MAC Address saved in @radius_data[:attributes][:mac]
  def normalize_mac!(data)
    raise ProtocolStackError.new "MAC Address is not available!" if data[:attributes][:mac].nil?
    data[:attributes][:mac].downcase!
    m_d = data[:attributes][:mac].match /^([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2}).*([0-9a-f]{2})$/
    if m_d && m_d.length == 7
      data[:attributes][:mac] = m_d[1, 6].join ":"
    else
      logger.warn "Found bad formatted or invalid MAC-Address: #{data[:attributes][:mac]} Falling back to default."
      data[:attributes][:mac] = "ff:ff:ff:ff:ff:ff"
    end
  end

  # Parse from the EAP Layer upwards
  def parse_from_eap

    raise ProtocolStackError.new "The EAP Stream must not be empty" if @eap_stream.nil?
    raise ProtocolStackError.new "The EAP Stream ist not an EAPStream Object" unless @eap_stream.is_a? EAPStream
    # First Parse EAP Metadata
    @eap_data[:information] = {}
    @eap_data[:information][:eap_identity] = @eap_stream.eap_identity
    @eap_data[:information][:initial_eaptype] = EAPPacket::Type::get_type_name_by_code(@eap_stream.initial_eap_type)
    @eap_data[:information][:wanted_eaptypes] = []
    @eap_stream.wanted_eap_types.each do |t|
      @eap_data[:information][:wanted_eaptypes] << EAPPacket::Type::get_type_name_by_code(t)
    end
    @eap_data[:information][:actual_eaptype] = EAPPacket::Type::get_type_name_by_code(@eap_stream.eap_type)
    @eap_data[:information][:roundtrips] = @eap_stream.eap_packets.length

    @eap_data[:information][:max_server_pkt_size] = 0
    @eap_data[:information][:max_client_pkt_size] = 0
    @eap_data[:information][:total_server_pkt_size] = 0
    @eap_data[:information][:total_client_pkt_size] = 0

    @eap_data[:information].merge!(parse_packetsize(@eap_stream.eap_packets) { |x| x.length })

    # Here is now decided how to proceed with the packet.
    case @eap_stream.eap_type
    when nil
      # This EAP Stream contains most likely a failed agreement between Client and server
      logger.debug "Seen Failed EAP Communication."
    when EAPPacket::Type::TTLS,
        EAPPacket::Type::PEAP,
        EAPPacket::Type::TLS
      logger.debug 'Found an EAP-TLS based EAP Type'
      @eap_tls_stream = EAPTLSStream.new(@eap_stream.eap_payload_packets)
      parse_from_eaptls

    when EAPPacket::Type::EAPPWD
      logger.info 'Found EAP-PWD Communication'
    when EAPPacket::Type::MD5CHALLENGE
      logger.info 'Found MD5CHALLENGE Communication'
    when EAPPacket::Type::MSEAP
      logger.info 'Found MSEAP Communication'
    else
      logger.warn "Unknown EAP Type #{@eap_stream.eap_type}"
    end

    logger.debug 'EAP Data: ' + @eap_data.to_s
  end

  # Parse from the EAP-TLS Layer upwards
  def parse_from_eaptls
    raise ProtocolStackError.new 'The EAP-TLS Stream must not be empty' if @eap_tls_stream.nil?
    raise ProtocolStackError.new 'The EAP-TLS Stream ist not an EAPTLSStream Object' unless @eap_tls_stream.is_a? EAPTLSStream

    # Parse EAP-TLS Metadata
    @tls_stream = TLSStream.new @eap_tls_stream.packets

    # If we captured an alert, we dont need to save it.
    if @tls_stream.alerted
      @dontsave = true
      return
    end

    tlspackets = @tls_stream.tlspackets
    # Now we have some assumptions. This might be a little
    # TLS Client Hello
    raise ProtocolStackError.new 'The first EAP-TLS Packet does not exist' if tlspackets.first.nil?
    raise ProtocolStackError.new 'The first EAP-TLS Packet contained not exactly one Record' if tlspackets.first.length != 1
    client_hello = tlspackets.first[0]
    raise ProtocolStackError.new 'The supposed TLS Client Hello was not a TLSHandshakeRecord' unless client_hello.is_a? TLSHandshakeRecord
    tlsclienthello = TLSClientHello.new(client_hello.data)
    @tls_data[:tlsclienthello] = tlsclienthello.to_h

    raise ProtocolStackError.new 'The next EAP-TLS Packet with the ServerHello does not exist' if tlspackets[1].nil?
    tlsserverhello = TLSServerHello.new(tlspackets[1])
    @tls_data[:tlsserverhello] = tlsserverhello.to_h

    if tlsserverhello.additional[:resumption]
      # If this is a Session Resumption, we don't save the data but just log the incident.
      @dontsave = true
    end

    logger.debug 'TLS Data: ' + @tls_data.to_s
  end

  # Initialize all class variables
  def initialize_variables
    @radius_data = {}
    @radius_stream = nil
    @radsec_data = {}
    @radsec_stream = nil
    @eap_data = {}
    @eap_stream = nil
    @eap_tls_data = {}
    @eap_tls_stream = nil
    @tls_data = {}
    @dontsave = false
  end
end