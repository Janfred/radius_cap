require './tlsciphersuites.rb'

class TLSServerHelloError < StandardError
end

class TLSServerHello
  attr_reader :outervers
  attr_reader :innervers
  attr_reader :random
  attr_reader :sessionid
  attr_reader :cipher
  attr_reader :compression
  attr_reader :extensions
  attr_reader :certificates
  attr_reader :additional

  def to_h
    to_ret = {}
    to_ret[:version] = case @innervers
      when [0x03, 0x03]; "TLSv1.2";
      when [0x03, 0x02]; "TLSv1.1";
      when [0x03, 0x01]; "TLSv1.0";
      else
        "Unknown"
    end
    to_ret[:renegotiation] = !!@byexten[TLSTypes::Extensions::RenegotiationInfo]
    to_ret[:extendedmastersecret] = !!@byexten[TLSTypes::Extensions::ExtendedMasterSecret]
    if @byexten[TLSTypes::Extensions::SupportedVersions] then
      to_ret[:version] = "TLSv1.3" if @byexten[TLSTypes::Extensions::SupportedVersions] == [0x03, 0x04]
    end
    to_ret[:cipher] = "0x%02X%02X" % @cipher
    to_ret[:cipherdata] = {}
    to_ret[:cipherdata]["FS"] = TLSCipherSuite.by_arr(@cipher)[:pfs]
    to_ret
  end


  def inspect
    str  = "#<#{self.class.name}:"
    #str += " v1.2" if @innververs == 0x0303
    #str += " Cipher:"
    #str += " 0x%02X%02X" % @cipher
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
    cur_ptr = 0
    while cur_ptr < data.length do
      outertype = data[cur_ptr]
      @outervers = data[cur_ptr+1, 2]
      outerlength = data[cur_ptr+3]*256 + data[cur_ptr+4]
      cur_ptr += 5
      type = data[cur_ptr]
      length = data[cur_ptr+1]*256*256 + data[cur_ptr+2]*256 + data[cur_ptr+3]
      if outerlength-length != 4 then
        raise TLSServerHelloError, 'Outer Length and Inner Length did not match'
      end
      case type
        when TLSTypes::HandshakeType::SERVERHELLO
          parse_serverhello data[cur_ptr+4, length]
        when TLSTypes::HandshakeType::CERTIFICATE
          parse_certificate data[cur_ptr+4, length]
        when TLSTypes::HandshakeType::SERVERKEYEXCHANGE
          parse_serverkeyexchange data[cur_ptr+4, length]
        when TLSTypes::HandshakeType::SERVERHELLODONE
          parse_serverhellodone data[cur_ptr+4, length]
        else
          $stderr.puts "Unknown TLS Handshaketype #{type}"
      end
      cur_ptr += outerlength
    end
  end

  def parse_serverhello(data)
    @innervers = data[0, 2]
    cur_ptr = 2

    @random = data[cur_ptr, 32]
    cur_ptr += 32

    # Session ID (optional)
    sessionid_len = data[cur_ptr]
    cur_ptr += 1
    @sessionid = data[cur_ptr, sessionid_len]
    cur_ptr += sessionid_len

    # Chosen Cipher
    @cipher = data[cur_ptr, 2]
    cur_ptr += 2

    # Compression
    @compression = data[cur_ptr]
    cur_ptr += 1

    raise TLSServerHelloError if data.length < cur_ptr

    @extensions = []
    @byexten = {}
    # Extensions
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
      exten[:data] = data[cur_ptr, exten[:length]]
      cur_ptr += exten[:length]
      @extensions << exten
      @byexten[exten[:type]] = exten[:data]
    end
  end
  def parse_certificate(data)
    cur_ptr = 0
    cert_length = data[0]*256*256 + data[1]*256 + data[2]
    cur_ptr += 3
    cert_end = cur_ptr + cert_length
    while cur_ptr < cert_end do
      this_length = data[cur_ptr]*256*256 + data[cur_ptr+1]*256 + data[cur_ptr+2]
      cur_ptr += 3
      @certificates ||= []
      @certificates << data[cur_ptr, this_length]
      cur_ptr += this_length
    end
  end
  def parse_serverkeyexchange(data)
    # Not yet implemented
    return
  end
  def parse_serverhellodone(data)
    # Nothing to do.
    return
  end
end
