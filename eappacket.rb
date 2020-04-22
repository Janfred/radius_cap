class EAPPacket
  module Code
    REQUEST  = 1
    RESPONSE = 2
    SUCCESS  = 3
    FAILURE  = 4
  end
  module Type
    IDENTITY     =  1
    NAK          =  3
    MD5CHALLENGE =  4
    TLS          = 13
    TTLS         = 21
    PEAP         = 25
    MSEAP        = 26
    EAPPWD       = 52
  end

  module TLSFlags
    LENGTHINCLUDED = 0x80
    MOREFRAGMENTS  = 0x40
    START          = 0x20
  end

  attr_accessor :code
  attr_accessor :identifier
  attr_accessor :length
  attr_accessor :type
  attr_accessor :type_data

  def initialize(data)
    @code = data[0]
    @identifier = data[1]
    @length = data[2]*256 + data[3]

    if @length != data.length
      raise PacketLengthNotValidError, 'EAP Length does not match data length'
    end

    return if @code == EAPPacket::Code::SUCCESS || @code == EAPPacket::Code::FAILURE

    raise PacketLengthNotValidError, 'Packet too short' if @length < 5

    @type = data[4]
    @type_data = data[5..-1]
  end
end
