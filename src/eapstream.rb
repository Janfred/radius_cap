# Class for EAP Stream. This then does the distinction between EAP-TLS communication
# (EAP-TLS, EAP-TTLS, EAP-PEAP) and all other EAP Communication
# @!attribute [r] first_eap_payload
#   @return [Integer] Packet with the first Payload content. Usually it is the second packet
#     but it may also be the fourth, if a NAK is captured.
# @!attribute [r] initial_eap_payload
#   @return [Integer] This is the initial offered EAP Type by the server.
#     It can differ from the selected EAP Type, e.g. if the Server supports
#     both EAP-TTLS and EAP-PEAP and it is set to default to PEAP, but the Clients are
#     configured to use TTLS.
# @!attribute [r] eap_packets
#   @return [Array<EAPPacket>] Parsed EAP Packets
# @!attribute [r] eap_type
#   @return [Integer] EAP Type of the communication in this stream. Might be nil, if the
#     client and server don't agree on an EAP Type.
# @!attribute [r] wanted_eap_types
#   @return [Array<Integer>] Requested EAP Types of the client. Defaults to empty Array and is only changed if the initial eap type suggested
#     by the server does not match the actual EAP Type or the Server rejects the wanted
#     EAP Type (e.g. because the client is configured to do EAP-PWD, but the server does not
#     support it.)
# @!attribute [r] eap_identity
#   @return [String] EAP Identity
class EAPStream
  include SemanticLogger::Loggable

  attr_reader :eap_packets, :eap_type, :initial_eap_type, :wanted_eap_types, :first_eap_payload, :eap_identity

  # Initialize the EAP Stream. Parses the EAP Type and matches the EAP fragmentation (not the EAP-TLS Fragmentation!)
  # @param pktstream [RadiusStream,RadsecStream,Array] Packet Stream
  # @raise [EAPStreamError] if the EAP Stream was invalid in any way.
  # @todo I should read the EAP RFC. I suspect that the EAP Communication is always <Response, Request>+,Response,[Success|Failure] but I'm not sure about that
  def initialize(pktstream)
    @eap_packets = []
    @eap_type = nil
    @wanted_eap_types = []
    @initial_eap_type = nil
    @first_eap_payload = nil
    @eap_identity = ""
    if pktstream.is_a?(RadiusStream) || pktstream.is_a?(RadsecStream)
      logger.trace("Initialize new EAP Stream. Packet Stream length: #{pktstream.packets.length}")
      # Here the EAP Stream is parsed based on the RADIUS Packets.
      pktstream.packets.each do |radius_packet|
        eap_msg = []
        radius_packet.attributes.each do |attr|
          next unless attr[:type] == RadiusPacket::Attribute::EAPMESSAGE
          eap_msg += attr[:data]
        end
        if eap_msg == []
          case radius_packet.packettype
          when RadiusPacket::Type::ACCEPT,
              RadiusPacket::Type::REJECT
            logger.trace 'Seen empty EAP Message with a Accept or Reject type'
            next
          else
            StatHandler.increase :eaperror_other
            logger.error 'Seen a RADIUS Packet without an EAP Content and it was not a final Message'
            raise EAPStreamError.new 'Ongoing RADIUS Packet without EAP Content captured'
          end
        end
        logger.trace 'EAP Content: ' + eap_msg.pack('C*').unpack('H*').first

        @eap_packets << EAPPacket.new(eap_msg)
      end
    elsif pktstream.is_a? Array
      logger.trace("Initialize new EAP Stream. Packet Stream length: #{pktstream.length}")
      pktstream.each do |pkt|
        @eap_packets << EAPPacket.new(pkt)
      end
    end

    if @eap_packets.length < 2
      StatHandler.increase :eaperror_communcation_too_short
      logger.warn 'The EAP Stream was less then 2 messages long. This won\'t be a valid EAP communication'
      raise EAPStreamError.new 'The Communication is too short (less then 2 messages long)'
    end

    set_eap_type
  end

  # Private helper function to determine the EAP Type.
  # @raise EAPStreamError if the EAP Communication violates the EAP RFC
  def set_eap_type
    # The first EAP Packet is always a EAP Response (For some weird reasons)
    # and EAP Type is Identity.
    # If this is not the case, the EAP Communication was most likely not captured completely.
    logger.trace("Code of the first EAP Packet: #{@eap_packets[0].code}")
    logger.trace("Type of the first EAP Packet: #{@eap_packets[0].type}")
    if @eap_packets[0].code != EAPPacket::Code::RESPONSE
      StatHandler.increase :eaperror_other
      raise EAPStreamError.new "The first EAP Packet has not a Response Code"
    end
    if @eap_packets[0].type != EAPPacket::Type::IDENTITY
      StatHandler.increase :eaperror_first_not_identity
      raise EAPStreamError.new "The first EAP Packet is not an Identity Type"
    end

    eap_identity_bytes = @eap_packets[0].type_data
    @eap_identity = eap_identity_bytes.pack('C*')

    @initial_eap_type = nil
    @wanted_eap_types = []
    @eap_type = nil

    # The Answer by the server is either an EAP Failure, in which case the Server
    # rejected the Client immediately or an EAP Request. If it is not, something is wrong.
    return if @eap_packets[1].code == EAPPacket::Code::FAILURE
    if @eap_packets[1].code != EAPPacket::Code::REQUEST
      StatHandler.increase :eaperror_other
      raise EAPStreamError
    end

    # Now we check for the EAP Type.
    # The initial message by the server contains the Server Default EAP Method
    @initial_eap_type = @eap_packets[1].type

    # Now that we have the initial EAP type we have to make sure that the client continues
    # talking to the server and does not reject the suggested EAP Type
    if @eap_packets[2].nil?
      StatHandler.increase :eaperror_communcation_too_short
      raise EAPStreamError.new "EAP Communication ended after 2 Messages"
    end

    cur_ptr = 2
    # CAUTION: I have witnessed a case where the client retransmitted the EAP-Identity. This case will be handled here
    if @eap_packets[cur_ptr].type == EAPPacket::Type::IDENTITY
      logger.warn "Seen a retransmission of the EAP Identity at packet #{cur_ptr}"
      if @eap_packets[cur_ptr+1].type != @initial_eap_type
        StatHandler.increase :eaperror_other
        raise EAPStreamError.new "The Server answered to a EAP-Identity Retransmission with a different type then he did before."
      end
      logger.warn 'EAP-Identities did not match' if @eap_packets[cur_ptr].type_data == eap_identity_bytes
      cur_ptr += 2
    end

    if @eap_packets[cur_ptr].type == @initial_eap_type
      # If the client answers with the same EAP Type we have a successful agreement
      # on the EAP type. We're done here.
      @eap_type = @initial_eap_type
      @first_eap_payload = cur_ptr - 1
      logger.trace "The first EAP Payload is in packet #{@first_eap_payload}"
      return nil
    end


    # If we're not done yet, the client most likely wants another EAP Type, so it
    # must answer with a Legacy NAK
    if @eap_packets[cur_ptr].type != EAPPacket::Type::NAK
      StatHandler.increase :eaperror_other
      raise EAPStreamError.new "The Client and Server want different EAP Types, but the Client did not send a NAK"
    end
    # Normally, the EAP NAK packet has a payload of 1 byte containing the desired auth type, but is it also allowed to send multiple EAP Types.
    if @eap_packets[cur_ptr].type_data.length == 0
      StatHandler.increase :eaperror_other
      raise EAPStreamError.new 'The Client\'s NAK did not contain a desired EAP Type.'
    end
    logger.debug "The client's NAK had more then one wanted eap type (#{@eap_packets[cur_ptr].type_data})" if @eap_packets[cur_ptr].type_data.length != 1

    @wanted_eap_types = @eap_packets[cur_ptr].type_data

    cur_ptr += 1

    # Now the client has stated it's desired auth type. We are now parsing the Servers answer to that.
    if @eap_packets[cur_ptr].nil?
      StatHandler.increase :eaperror_unexpected_end
      raise EAPStreamError.new 'The Client sent a NAK but the server didn\'t answer'
    end

    # We now have to determine between a rejection and a success in agreement.
    if @eap_packets[cur_ptr].code == EAPPacket::Code::FAILURE
      # If the Server answers with a Failure, it probably does not support
      # the desired auth type. In any case, the EAP Type is then set to nil.
      @eap_type = nil
      logger.debug 'This EAP Stream ends with a Failure after the fourth packet'
      return nil
    end

    # If the server didn't reject the client, we just need to make sure the Server actually answeres
    # with a packet that matches the desired auth type sent by the client
    unless @wanted_eap_types.include?(@eap_packets[3].type)
      StatHandler.increase :eaperror_other
      raise EAPStreamError.new 'The Server answered with a different EAP Type then the Client requested'
    end

    # If this wasn't the case, we finally know our EAP Type.
    @eap_type = @eap_packets[cur_ptr].type
    @first_eap_payload = cur_ptr

    logger.trace "The first EAP Payload is in packet #{@first_eap_payload}"

    # And then we return nil to not confuse the caller with our return value
    nil
  end
  private :set_eap_type

  # Get Only Packets with the EAP Payload
  # @return [Array<EAPPacket>] Packets containing the EAP Payload
  def eap_payload_packets
    @eap_packets[@first_eap_payload..-1]
  end
end

# Error to be thrown when the EAP Protocol is violated
class EAPStreamError < StandardError
end

# Stream of EAP-TLS Packets.
# This class handles some properties of the EAP-TLS specification e.g. the Fragmentation.
# As a result the packets objects included contain only the pure EAP-TLS communication
# without the Meta-Packets (EAP-TLS Start, Acknowledgements for fragmented packets, ...)
# The first packet in the internal packet Array is the EAP-TLS Client Hello. The initial EAP-TLS Start is
# parsed, but left out.
class EAPTLSStream
  include SemanticLogger::Loggable

  attr_reader :packets
  @packets

  # Initialize new EAP-TLS Stream
  # @param eapstream [Array<EAPPacket>] EAP Stream to parse
  def initialize(eapstream)

    raise EAPStreamError.new "The EAP Stream is to short to be an actually EAP-TLS Communication" if eapstream.length < 2

    firstpkt = eapstream.first
    # Error Message intentionally left blank.
    raise EAPStreamError if firstpkt.nil?
    raise EAPStreamError unless firstpkt.is_a? EAPPacket
    current_eaptype = firstpkt.type

    @packets = []

    # If the eapstream is shorter then two messages there must be something wrong.

    cur_pkt = 0
    frag = EAPTLSFragment.new(eapstream[cur_pkt].type_data)
    # The first packet is A EAP-TLS Start (Only the Start Flag set)
    raise EAPStreamError.new "The first fragment was no EAP-TLS Start Packet" unless frag.is_start?

    # Now we have verified the EAP-TLS Start.
    cur_pkt += 1

    # Now we go on parsing all packets until we have a success/failure
    while eapstream[cur_pkt].type == current_eaptype do
      cur_pkt_data = []
      indicated_length = 0
      begin
        logger.trace "Parsing packet #{cur_pkt}"
        raise EAPStreamError.new "EAP Communication ended unexpectedly" if eapstream[cur_pkt].nil?
        logger.trace "EAP Type of the packet: #{eapstream[cur_pkt].type}"
        raise EAPStreamError.new "The EAP Type of the current packet does not match the EAP Type of the other EAP Packets" if eapstream[cur_pkt].type != current_eaptype
        frag = EAPTLSFragment.new(eapstream[cur_pkt].type_data)

        if frag.is_acknowledgement?
          # I first thought this was an edge-case, but these fragments are actually sent on regular
          # bases, mostly as the last packet after the server (presumably) sends cryptographic information
          # inside the TLS Tunnel
          # This Packet is not yet the Accept-Packet, so the client needs to send an acknowledgement.
          # Practically, this will result in an empty packet inserted in the @packets.
          logger.debug 'Captured an acknowledgement packet after a Fragment without MoreFragments set'
        end
        cur_pkt_data += frag.payload
        more_fragments = frag.more_fragments?
        indicated_length = frag.indicated_length if indicated_length == 0
        logger.trace "Indicated Packet Length: #{indicated_length}"
        logger.trace "Current Fragment Length: #{frag.payload.length}"
        logger.trace "Current Packet Length: #{cur_pkt_data.length}"

        # If the sent packet had more fragments then the other communication partner has to acknowledge
        # the Packet. This is done by sending an empty packet with no flags set.
        if more_fragments
          cur_pkt += 1

          raise EAPStreamError.new "A EAP Fragment with MoreFragments set was left unacknowledged" if eapstream[cur_pkt].nil?

          raise EAPStreamError.new "The EAP Type of the acknowledgement packet does not match the EAP Type of the other EAP Packets" if eapstream[cur_pkt].type != current_eaptype
          frag = EAPTLSFragment.new(eapstream[cur_pkt].type_data)

          raise EAPStreamError.new "The expected acknowledgement Packet is not actually an acknowledgement" unless frag.is_acknowledgement?

          logger.trace 'Acknowledgement'
          cur_pkt += 1
        end
      end while more_fragments
      raise EAPStreamError.new "The Indicated Length did not match the actual Length of the packet" if cur_pkt_data.length != indicated_length
      @packets << cur_pkt_data
      logger.trace 'Packet was parsed completely. Moving on to the next'
      cur_pkt += 1
      raise EAPStreamError.new "EAP Communication ended unexpectedly" if eapstream[cur_pkt].nil?
    end
    logger.trace 'Reached end of EAP-TLS communication'
  end
end

# Helper class for parsing the EAP Packets
class EAPTLSFragment
  include SemanticLogger::Loggable

  # Constants for EAP-TLS Flags
  module TLSFlags
    # Indicates, that the EAP Payload contains the Length of the EAP Payload
    LENGTHINCLUDED = 0x80
    # Indicates, that this EAP Packet is fragmented and that more fragments follow
    MOREFRAGMENTS  = 0x40
    # Indicates the Start of the EAP-TLS communication
    START          = 0x20
  end


  # Attribute reader for some attributes.
  # The other attributes have a dedicated getter method below.
  attr_reader :indicated_length, :payload

  # [Boolean] Is Start Flag set?
  @tlsstart
  # [Boolean] Is the Length Included Flag set?
  @length_included
  # [Boolean] Is the More Fragments Option set?
  @more_fragments
  # [Integer] Indicated Length as set by the EAP-TLS Length parameter.
  # Set to @payload_length if the Length Included Flag is not set.
  @indicated_length
  # [Array<Bytes>] Payload of the packet without Flags and Length
  @payload

  # Initalize new EAP TLS Fragment
  # @param data [Array<Byte>] Payload of the EAP TLS Fragment
  def initialize(data)
    # If the data is empty, then this can't be a EAP-TLS Fragment.
    raise EAPStreamError.new "The EAP Packet has no content" if data.length == 0

    logger.trace "Length of the EAP Packet: #{data.length}"
    flags = data[0]
    logger.trace "Flags: 0x%02X" % flags
    @length_included = (flags & EAPTLSFragment::TLSFlags::LENGTHINCLUDED) != 0
    @more_fragments = (flags & EAPTLSFragment::TLSFlags::MOREFRAGMENTS) != 0
    @tlsstart = (flags & EAPTLSFragment::TLSFlags::START) != 0

    logger.trace 'Included Flags:' + (@length_included ? ' Length included': '' ) +
                     (@more_fragments ? ' More Fragments' : '') +
                     (@tlsstart ? ' Start': '')

    @indicated_length = nil
    cur_ptr = 1
    if @length_included
      # If the length is included, then the data must be at least 5 bytes long.
      raise EAPStreamError.new "The EAP Packet is to short to contain a length" if data.length < 5
      @indicated_length = data[cur_ptr]*256*256*256 + data[cur_ptr+1]*256*256 + data[cur_ptr+2]*256 + data[cur_ptr+3]
      cur_ptr += 4
    end

    logger.trace("Parsing payload from position #{cur_ptr}")
    @payload = data[cur_ptr..-1]
    @indicated_length = @payload.length if @indicated_length.nil?
    logger.trace("The Payload is #{@payload.length} bytes long")

    logger.trace("Payload: #{@payload.inspect}") if @tlsstart

    # Last we check that if the Start flag is set, the payload is empty. Otherwise the Packet would violate
    # the protocol.
    raise EAPStreamError.new "The EAP-TLS Start flag was set but the Packet had content" if @tlsstart && @payload.length != 0
  end

  # Checks if the Fragment is an acknowledgement of a previous EAP-TLS Fragment.
  # This is the case when all flags are set to 0 and the payload is empty.
  # @return [Boolean] if the Fragment is an acknowledgement.
  def is_acknowledgement?
    !@tlsstart && !@length_included && !@more_fragments && @payload.length == 0
  end

  # Getter for the Start Flag
  # @return [Boolean]
  def is_start?
    @tlsstart
  end
  # Getter for the More Fragments Flag
  # @return [Boolean]
  def more_fragments?
    @more_fragments
  end
  # Getter for the Length Included Flag
  # @return [Boolean]
  def length_included?
    @length_included
  end
end
