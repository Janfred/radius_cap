# frozen_string_literal: true

# EAP Packet. This class does not handle EAP fragmentation itself.
# EAP is fragmented in two ways
# * Inside one Radius-Packet there can be multiple EAP-Messages. This usually sums up to approx 1000 Bytes EAP.
# If this is the case, the Payload of the EAP-Message Attributes is concatenated. The MoreFragments Flag will
# not be set, the Length might or might not be included.
# * If the EAP Message is longer then the maximum length per RADIUS-Packet (approx. 1000 Bytes) which happens
# especially in the TLS Server Hello) the EAP message has to be sent in multiple Radius-Packets.
# In this case the MoreFragments Flag is set. The Length will then be included in all EAP fragments.
class EAPPacket
  include SemanticLogger::Loggable

  # Constants for EAP Codes
  module Code
    # EAP REQUEST
    REQUEST  = 1
    # EAP RESPONSE
    RESPONSE = 2
    # EAP SUCCESS
    SUCCESS  = 3
    # EAP FAILURE
    FAILURE  = 4

    # Get EAP Code by the given code
    # @param code [Byte] Code of the EAP Code
    # @return [String] Name of the EAP Code, or "UNKNOWN_EAP_CODE_<num>" if EAP Type is unknown
    def self.get_code_name_by_code(code)
      return nil if code.nil?

      Code.constants.each do |const|
        next if Code.const_get(const) != code

        return const.to_s
      end
      "UNKNOWN_EAP_CODE_#{code}"
    end
  end

  # Constants for EAP Types
  # https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml
  module Type
    # Reserved code. This code should never be transmitted
    RESERVED       = 0
    # Sent by the Client in the first EAP Message.
    IDENTITY       =  1
    # (Also known as `Legacy Nak`) Rejection of the proposed EAP-Type.
    # Sent by the Client together with a desired EAP Type
    NAK            =  3
    # MD5 Challenge Type
    # @todo This is weird. This should actually never occur in the Eduroam environment because it is insecure.
    #   Maybe we should emit a warning once we see it
    MD5CHALLENGE   =  4
    # EAP Generic Token Card
    GTC            =  6
    # TLS Type (not TTLS or PEAP)
    TLS            = 13
    # EAP-Cisco Wireless
    # @todo I don't know what this is. Subject to research
    CISCO_WIRELESS = 17
    # EAP-SIM
    SIM            = 18
    # TTLS Type
    TTLS           = 21
    # PEAP Type
    PEAP           = 25
    # MSEAP Type
    # @todo I don't know what this is. Subject to research
    MSEAP          = 26
    # FAST Type
    # @todo This is also interesting to research
    FAST           = 43
    # EAP-PWD Type
    # @todo EAP-PWD is rudimentary analysed, but it will be interesting to analyse it deeper.
    EAPPWD         = 52
    # EAP-TEAP
    # @todo This will be very interesting.
    TEAP           = 55

    # Get EAP Type by the given code
    # @param code [Byte] Code of the EAP Type
    # @return [String] Name of the EAP Type, or "UNKNOWN_EAPTYPE_<num>" if EAP Type is unknown
    def self.get_type_name_by_code(code)
      return nil if code.nil?

      Type.constants.each do |const|
        next if Type.const_get(const) != code

        return const.to_s
      end
      "UNKNOWN_EAPTYPE_#{code}"
    end
  end

  # Constants for EAP-TLS Flags
  module TLSFlags
    # Indicates, that the EAP Payload contains the Length of the EAP Payload
    LENGTHINCLUDED = 0x80
    # Indicates, that this EAP Packet is fragmented and that more fragments follow
    MOREFRAGMENTS  = 0x40
    # Indicates the Start of the EAP-TLS communication
    START          = 0x20
  end

  # EAP Code (Request/Response/Success/Failure)
  attr_accessor :code
  attr_accessor :identifier
  # [Integer] Length of the EAP Payload
  attr_accessor :length
  # [Byte] EAP Type (Identity/Nak/MD5Challenge/TLS/TTLS/PEAP/MSEAP/EAPPWD)
  attr_accessor :type
  # [Array] Payload for the EAP Type
  attr_accessor :type_data

  # Parses an EAP packet
  # @param data Array of Bytes with payload
  # @return new Instance of EAPPacket
  def initialize(data)
    @code = data[0]
    @identifier = data[1]
    @length = data[2] * 256 + data[3]

    raise PacketLengthNotValidError, 'EAP Length does not match data length' if @length != data.length

    return if @code == EAPPacket::Code::SUCCESS || @code == EAPPacket::Code::FAILURE

    raise PacketLengthNotValidError, 'Packet too short' if @length < 5

    @type = data[4]
    @type_data = data[5..-1]
    logger.trace "EAP Type Content: #{@type_data.pack('C*').unpack1('H*')}"
  end
end
