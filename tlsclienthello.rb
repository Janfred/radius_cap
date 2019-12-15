class TLSClientHelloError < StandardError
end

module TLSTypes
  module RecordType
    HANDSHAKE = 0x16
  end
  module HandshakeType
    CLIENTHELLO = 0x01
  end
  module Extensions
    SupportedGroups      = 10
    ECPointFormats       = 11
    SignatureAlgorithms  = 13
    EncryptThenHMAC      = 22
    ExtendedMasterSecret = 23
  end
end

class TLSClientHello

  attr_reader :outervers
  attr_reader :outerlen
  attr_reader :innerlen
  attr_reader :innervers
  attr_reader :random
  attr_reader :sessionid
  attr_reader :ciphersuites
  attr_reader :compression
  attr_reader :extensions

  def inspect
    str  = "#<#{self.class.name}:"
    str += " v1.2" if @innververs == 0x0303
    str += " Cipher:"
    @ciphersuites.each do |c|
      str += " 0x%02X%02X" % c
    end
    @extensions.each do |e|
      case e[:type]
        when SupportedGroups
          str += " SupportedGroups"
        when ECPointFormats
          str += " ECPointFormats"
        when SignatureAlgorithms
          str += " SignatureAlgorithms"
        when EncryptThenHMAC
          str += " EncryptThenHMAC"
        when ExtendedMasterSecret
          str += " ExtendedMasterSecret"
        else
          $stderr.puts "Unsupported TLS Extension #{e[:type]}"
      end
    end
    str += ">"
    return str
  end

  def initialize(data)
    raise TLSClientHelloError unless data[0] == TLSTypes::RecordType::HANDSHAKE
    @outervers = data[1]*256 + data[2]
    @outerlen  = data[3]*256 + data[4]
    raise TLSClientHelloError, 'Not a TLS Client Hello' unless data[5] == TLSTypes::HandshakeType::CLIENTHELLO
    @innerlen = data[6]*256*256 + data[7]*256 + data[8]
    @innervers = data[9]*256 + data[10]
    @random = data[11..42]
    cur_ptr = 43

    # Session ID (optional)
    sessionid_len = data[cur_ptr]
    @session = data[cur_ptr+1..cur_ptr+sessionid_len]
    cur_ptr += sessionid_len+1

    # Available Ciphersuites
    cipher_len = data[cur_ptr]*256 + data[cur_ptr+1]
    cur_ptr += 2
    cipher_end = cur_ptr+cipher_len
    @ciphersuites = []
    while cur_ptr < cipher_end do
      @ciphersuites << [data[cur_ptr], data[cur_ptr+1]]
      cur_ptr += 2
    end

    # Compression Methods
    comp_len = data[cur_ptr]
    @compression = data[cur_ptr+1..cur_ptr+comp_len]
    cur_ptr += comp_len+1

    @extensions = []
    exten_len = 0

    if data.length < cur_ptr then
      # No extensions present
      return
    end

    exten_len = data[cur_ptr]*256 + data[cur_ptr+1]
    cur_ptr += 2
    exten_end = cur_ptr + exten_len
    while cur_ptr < exten_end do
      exten = {}
      exten[:type] = data[cur_ptr]*256 + data[cur_ptr+1]
      exten[:length] = data[cur_ptr+2]*256 + data[cur_ptr+3]
      cur_ptr += 4
      exten[:data] = data[cur_ptr..cur_ptr+exten[:length]-1]
      cur_ptr += exten[:length]
      @extensions << exten
    end
  end
end
