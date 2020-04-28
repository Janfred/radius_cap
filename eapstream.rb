# Class for EAP Stream. This then does the destiction between EAP-TLS communication
# (EAP-TLS, EAP-TTLS, EAP-PEAP) and all other EAP Communication
class EAPStream
  attr_reader :eap_packets, :eap_type, :initial_eap_type, :wanted_eap_type

  # [Array<EAPPacket>]
  @eap_packets

  # [Integer] EAP Type of the communication in this stream. Might be nil, if the client and server don't agree on
  # an EAP Type
  @eap_type

  # [Integer] Requested EAP Type of the client. Only set if the initial eap type suggested
  # by the server does not match the actual EAP Type or the Server rejects the wanted
  # EAP Type (e.g. because the client is configured to do EAP-PWD, but the server does not
  # support it.)
  @wanted_eap_type

  # [Integer] This is the initial offered EAP Type by the server.
  # It can differ from the selected EAP Type, e.g. if the Server supports
  # both EAP-TTLS and EAP-PEAP and it is set to default to PEAP, but the Clients are
  # configured to use TTLS.
  @initial_eap_type

  # Initialize the EAP Stream. Parses the EAP Type and matches the EAP fragmentation (not the EAP-TLS Fragmentation!)
  # @param pktstream [RadiusStream] Packet Stream
  # @raise [EAPStreamError] if the EAP Stream was invalid in any way.
  # @todo I should read the EAP RFC. I suspect that the EAP Communication is always {Response, Request}+,Response,[Success|Failure] but I'm not sure about that
  def initialize(pktstream)
    @eap_packets = []
    @eap_type = nil
    @wanted_eap_type = nil
    @initial_eap_type = nil
    # Here the EAP Stream is parsed based on the RADIUS Packets.
    pktstream.packets.each do |radius_packet|
      eap_msg = []
      radius_packet.attributes.each do |attr|
        next unless attr[:type] == RadiusPacket::Attribute::EAPMESSAGE
        eap_msg += attr[:data]
      end
      if eap_msg == []
        # TODO Here should be a warning or even an error unless this is the final answer
      end
      @eap_packets << EAPPacket.new(eap_msg)
    end

    if @eap_packets.length < 2
      # TODO This should be a message for the Logging
      $stderr.puts "The EAP Stream was less then 2 messages long. This won't be a valid EAP communication"
      # TODO This Error should have a message
      raise EAPStreamError
    end

    set_eap_type
  end

  # Private helper function to determine the EAP Type.
  # @raise EAPStreamError if the EAP Communication violates the EAP RFC
  def set_eap_type
    # The first EAP Packet is always a EAP Response (For some weird reasons)
    # and EAP Type is Identity.
    # If this is not the case, the EAP Communication was most likely not captured completely.
    # TODO This Error should have a message
    raise EAPStreamError if @eap_packets[0].code != EAPPacket::Code::RESPONSE
    # TODO This Error should have a message
    raise EAPStreamError if @eap_packets[0].type != EAPPacket::Type::IDENTITY

    # The Answer by the server is an EAP Request. If it is not, something is wrong.
    raise EAPStreamError if @eap_packets[1].code != EAPPacket::Code::REQUEST
    # Now we check for the EAP Type.
    # The initial message by the server contains the Server Default EAP Method
    @initial_eap_type = @eap_packets[1].type

    # Now that we have the initial EAP type we have to make sure that the client continues
    # talking to the server and does not reject the suggested EAP Type
    # TODO This Error should have a message
    raise EAPStreamError if @eap_packets[2].nil?

    if @eap_packets[2].type == @initial_eap_type
      # If the client answers with the same EAP Type we have a successful agreement
      # on the EAP type. We're done here.
      @eap_type = @initial_eap_type
      return nil
    end

    # If we're not done yet, the client most likely wants another EAP Type, so it
    # must answer with a Legacy NAK
    # TODO This Error should have a message
    raise EAPStreamError if @eap_packets[2].type != EAPPacket::Type::NAK
    # The EAP NAK packet has a payload of 1 byte containing the desired auth type.
    # TODO This Error should have a message. The check might even be moved to the EAPPacket parser.
    raise EAPStreamError if @eap_packets[2].type_data.length != 1

    @wanted_eap_type = @eap_packets[2].type_data[0]

    # Now the client has stated it's desired auth type. We are now parsing the Servers answer to that.
    # TODO This Error should have a message.
    raise EAPStreamError if @eap_packets[3].nil?

    # We now have to determine between a rejection and a success in agreement.
    if @eap_packets[3].code == EAPPacket::Code::FAILURE
      # If the Server answers with a Failure, it probably does not support
      # the desired auth type. In any case, the EAP Type is then set to nil.
      @eap_type = nil
      return nil
    end

    # If the server didn't reject the client, we just need to make sure the Server actually answeres
    # with a packet that matches the desired auth type sent by the client
    # TODO This Error should have a message.
    raise EAPStreamError if @eap_packets[3].type != @wanted_eap_type

    # If this wasn't the case, we finally know our EAP Type.
    @eap_type = @wanted_eap_type

    # And then we return nil to not confuse the caller with our return value
    nil
  end
  private :set_eap_type
end

# Error to be thrown when the EAP Protocol is violated
class EAPStreamError < StandardError
end

# Stream of EAP-TLS Packets.
# This class handles some properties of the EAP-TLS specification e.g. the Fragmentation.
# As a result the [[EAPTLSPacket]] objects included contain only the pure EAP-TLS communication
# without the Meta-Packets (EAP-TLS Start, Acknowledgements for fragmented packets, ...)
class EAPTLSStream

end

# EAP TLS Packet
class EAPTLSPacket

end