class TLSClientHelloError < StandardError
end

module TLSTypes
  module RecordType
    HANDSHAKE = 0x16
  end
  module HandshakeType
    CLIENTHELLO       =  1
    SERVERHELLO       =  2
    CERTIFICATE       = 11
    SERVERKEYEXCHANGE = 12
    SERVERHELLODONE   = 14
  end
  module Extensions
    ServerName           =     0
    StatusRequest        =     5
    SupportedGroups      =    10
    ECPointFormats       =    11
    SignatureAlgorithms  =    13
    Heartbeat            =    15
    SignedCertTimestamp  =    18
    EncryptThenHMAC      =    22
    ExtendedMasterSecret =    23
    SessionTicket        =    35
    SupportedVersions    =    43
    PSKKeyExchangeModes  =    45
    KeyShare             =    51
    RenegotiationInfo    = 65281
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
        when TLSTypes::Extensions::ServerName
          str += " ServerName"
        when TLSTypes::Extensions::StatusRequest
          str += " StatusRequest"
        when TLSTypes::Extensions::SupportedGroups
          str += " SupportedGroups"
        when TLSTypes::Extensions::ECPointFormats
          str += " ECPointFormats"
        when TLSTypes::Extensions::SignatureAlgorithms
          str += " SignatureAlgorithms"
        when TLSTypes::Extensions::Heartbeat
          str += " Heartbeat"
        when TLSTypes::Extensions::SignedCertTimestamp
          str += " SignedCertTimestamp"
        when TLSTypes::Extensions::EncryptThenHMAC
          str += " EncryptThenHMAC"
        when TLSTypes::Extensions::ExtendedMasterSecret
          str += " ExtendedMasterSecret"
        when TLSTypes::Extensions::SessionTicket
          str += " SessionTicket"
        when TLSTypes::Extensions::SupportedVersions
          str += " SupportedVersions"
        when TLSTypes::Extensions::PSKKeyExchangeModes
          str += " PSKKeyExchangeModes"
        when TLSTypes::Extensions::KeyShare
          str += " KeyShare"
        when TLSTypes::Extensions::RenegotiationInfo
          str += " RenegotiationInfo"
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

    if data.length <= cur_ptr then
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
