# frozen_string_literal: true

# Class for EAPPWD Fragments
class EAPPWDFragment
  include SemanticLogger::Loggable

  # Module for EAP-PWD Fragment Flags
  module Flags
    # Indicates, that the EAP Payload contains the Length of the EAP Payload
    LENGTHINCLUDED = 0x80
    # Indicates, that this EAP Packet is fragmented and that more fragments follow
    MOREFRAGMENTS  = 0x40
    # Mask for PWD-Exch (see [PWDEXCHTypes])
    PWDEXCHBITS    = 0x3F
  end

  # Module for EAP-PWD Exchange Types (encoded in Flag byte)
  module PWDEXCHTypes
    # Reserved Type
    RESERVED = 0x00
    # EAP-PWD ID Type
    ID       = 0x01
    # EAP-PWD Commit Type
    COMMIT   = 0x02
    # EAP-PWD Confirm Type
    CONFIRM  = 0x03

    # Get the name of a given PWDEXCHType by the given code
    # @param code [Integer] PWDEXCHType as int
    # @return [String] the constant name of the given Type, UNKNOWN_PWDEXCH_<num> if unknown
    def self.get_name_by_code(code)
      PWDEXCHTypes.constants.each do |const|
        next if PWDEXCHTypes.const_get(const) != code

        return const.to_s
      end
      "UNKNOWN_PWDEXCH_#{code}"
    end
  end

  attr_reader :indicated_length, :payload, :exch_type

  @length_included
  @more_fragments
  @indicated_length
  @payload
  @exch_type

  # Create new Instance of the class
  # @param data [Array<Byte>] EAP-PWD Fragment as Byte-Array
  def initialize(data)
    if data.empty?
      @payload = []
      @more_fragments = false
      @length_included = false
      @exch_type = nil
    end
    logger.trace "Length of the EAP Packet: #{data.length}"
    flags = data[0]
    logger.trace 'Flags/PWD-Exch: 0x%02X' % flags
    @length_included = (flags & EAPPWDFragment::Flags::LENGTHINCLUDED) != 0
    @more_fragments = (flags & EAPPWDFragment::Flags::MOREFRAGMENTS) != 0
    @exch_type = (flags & EAPPWDFragment::Flags::PWDEXCHBITS)

    logger.trace "PWD-Exch #{PWDEXCHTypes.get_name_by_code(@exch_type)}" \
                 " Flags: #{@length_included ? ' Length included' : ''}#{@more_fragments ? ' More Fragments' : ''}"

    @indicated_length = nil
    cur_ptr = 1
    if @length_included
      raise EAPStreamError, 'The EAP Packet is to short to contain a length' if data.length < 3

      @indicated_length = data[cur_ptr] * 256 + data[cur_ptr + 1]
      cur_ptr += 2
    end
    logger.trace("Parsing payload from position #{cur_ptr}")
    @payload = data[cur_ptr..-1]
    @indicated_length = @payload.length if @indicated_length.nil?
  end

  # Check if LENGTH_INCLUDED flag is set
  # @return [Boolean] if LENGTH_INCLUDED flag is set
  def length_included?
    @length_included
  end

  # Check if MORE_FRAGMENTS flag is set
  # @return [Boolean] if MORE_FRAGMENTS flag is set
  def more_fragments?
    @more_fragments
  end

  # Check if current fragment is an acknowledgement fragment
  # @return [Boolean] if current fragment is an acknowledgement fragment
  def acknowledgement?
    @payload.empty? && !@more_fragments && !@length_included && @exch_type.nil?
  end
end

# Stream of EAP-PWD Packets.
# This class handles some properties of the EAP-PWD specification e.g. the Fragmentation.
class EAPPWDStream
  include SemanticLogger::Loggable

  attr_reader :packets

  @packets

  # Create new Instance of the class
  # @param eapstream [Array<EAPPacket>] EAP Stream as Array of EAPPacket
  def initialize(eapstream)
    raise EAPStreamError, 'The EAP Stream is to short to be an actually EAP-PWD Communication' if eapstream.length < 2

    logger.trace "Parsing PWD Stream of length #{eapstream.length}"
    firstpkt = eapstream.first
    raise EAPStreamError if firstpkt.nil?
    raise EAPStreamError unless firstpkt.is_a? EAPPacket

    current_eaptype = firstpkt.type

    @packets = []

    cur_pkt = 0
    while eapstream[cur_pkt].type == current_eaptype
      cur_pkt_data = []
      cur_pkt_type = nil
      indicated_length = 0
      loop do
        logger.trace "Parsing packet ##{cur_pkt}"
        frag = EAPPWDFragment.new(eapstream[cur_pkt].type_data)
        if frag.acknowledgement?
          logger.debug 'Captured EAP-PWD Acknowledgement after Fragment without MoreFragments set'
        end

        cur_pkt_type ||= frag.exch_type
        if cur_pkt_type != frag.exch_type
          raise EAPStreamError, 'A second EAP-PWD Fragment with a different type then the previous has been captured'
        end

        cur_pkt_data += frag.payload
        more_fragments = frag.more_fragments?
        indicated_length = frag.indicated_length if indicated_length.zero?

        if more_fragments
          cur_pkt += 1

          if eapstream[cur_pkt].nil?
            raise EAPStreamError, 'An EAP-PWD Fragment with MoreFragments set was left unacknowledged'
          end

          if eapstream[cur_pkt].type != current_eaptype
            raise EAPStreamError, 'The EAP-Type of the acknowledgement packet does not match the' \
            ' EAP Type of the other EAP Packets'
          end

          logger.trace "Parsing supposed acknowledgement packet ##{cur_pkt}"
          frag = EAPPWDFragment.new(eapstream[cur_pkt].type_data)

          unless frag.acknowledgement?
            raise EAPStreamError, 'The expected acknowledgement Packet is not actually an acknowledgement'
          end

          logger.trace 'Acknowledgement'
          cur_pkt += 1
        end
        break unless more_fragments
      end

      if cur_pkt_data.length != indicated_length
        raise EAPStreamError, 'The indicated Length did not match the actual Length of the packet'
      end

      @packets << { type: cur_pkt_type, data: cur_pkt_data }
      logger.trace 'Packet was parsed completely. Moving to the next'
      cur_pkt += 1
      raise EAPStreamError, 'EAP Communication ended unexpectedly' if eapstream[cur_pkt].nil?
    end
    logger.trace 'Reached end of EAP-PWD Communication'
  end
end

# EAP PWD Packet module
module PWDPackets
  # EAP-PWD ID Packet
  class ID
    attr_reader :group, :random_func, :prf, :token, :prep, :identity

    def initialize(data)
      @group = data[0] * 256 + data[1]
      @random_func = data[2]
      @prf = data[3]
      @token = data[4..7]
      @prep = data[8]
      @identity = data[9..-1]
    end
  end
end

# Parser Class for an EAP-PWD Stream
class PWDStream
  include SemanticLogger::Loggable
  attr_reader :data

  # @todo This method raises a StandardError. This should be fixed.
  # @todo This Method is also currently just a stub, it needs to be extended. But for now I think this is a good start.
  def initialize(packets)
    # EAP-PWD is a strictly 6 Message protocol.
    # raise StandardError unless packets.length == 6
    raise StandardError if packets.length < 2
    # First we have 2 EAP-pwd-ID Messages
    raise StandardError unless packets[0][:type] == EAPPWDFragment::PWDEXCHTypes::ID

    server_id_pkt = PWDPackets::ID.new(packets[0][:data])
    raise StandardError unless packets[1][:type] == EAPPWDFragment::PWDEXCHTypes::ID

    peer_id_pkt = PWDPackets::ID.new(packets[1][:data])

    @data = {}
    @data[:group]     = '0x%04X' % server_id_pkt.group
    @data[:rand_func] = '0x%02X' % server_id_pkt.random_func
    @data[:prf]       = '0x%02X' % server_id_pkt.prf
    @data[:prep]      = '0x%02X' % server_id_pkt.prep
  end
end
