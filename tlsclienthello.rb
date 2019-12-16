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
  module ExtenData
    module ServerName
      HostName = 0
    end
    module StatusRequest
      OCSP = 1
    end
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

  def to_h
    to_ret = {}
    to_ret[:version] = case @innervers
      when [0x03, 0x03]
        "TLSv1.2"
      when [0x03, 0x02]
        "TLSv1.1"
      when [0x03, 0x01]
        "TLSv1.0"
      else
        "Unknown"
    end
    to_ret[:renegotion] = @ciphersuites.include?([0x00,0xFF]) || !!@byexten[TLSTypes::Extensions::RenegotiationInfo]
    to_ret[:servername] = parse_servername(@byexten[TLSTypes::Extensions::ServerName]) if @byexten[TLSTypes::Extensions::ServerName]
    to_ret[:extendedmastersecret] = !!@byexten[TLSTypes::Extensions::ExtendedMasterSecret]
    if @byexten[TLSTypes::Extensions::SupportedVersions] then
      ver = parse_supported_versions(@byexten[TLSTypes::Extensions::SupportedVersions])
      to_ret[:version] = "TLSv1.3" if ver.include? [0x03, 0x04]
    end
    if @byexten[TLSTypes::Extensions::SupportedGroups] then
      to_ret[:supportedgroups] = parse_supported_groups(@byexten[TLSTypes::Extensions::SupportedGroups])
    else
      to_ret[:supportedgroups] = []
    end
    if @byexten[TLSTypes::Extensions::StatusRequest] then
      to_ret[:statusrequest] = parse_status_request(@byexten[TLSTypes::Extensions::StatusRequest])
    else
      to_ret[:statusrequest] = []
    end
    if @byexten[TLSTypes::Extensions::SignatureAlgorithms] then
      to_ret[:signaturealgorithms] = parse_signature_algorithms(@byexten[TLSTypes::Extensions::SignatureAlgorithms])
    else
      to_ret[:signaturealgorithms] = []
    end
    to_ret[:ciphersuites] = @ciphersuites.map {|c| "0x%02X%02X" % c}
    to_ret
  end

  def parse_signature_algorithms(data)
    length = data[0]*256 + data[1]
    return if data.length != length + 2
    cur_ptr = 2
    to_ret = []
    while cur_ptr < data.length do
      to_ret << case data[cur_ptr, 2]
        when [0x02, 0x01]; "rsa_pkcs1_sha1";
        when [0x02, 0x02]; "SHA1 DSA";
        when [0x02, 0x03]; "ecdsa_sha1";
        when [0x03, 0x01]; "SHA224 RSA";
        when [0x03, 0x02]; "SHA224 DSA";
        when [0x03, 0x03]; "SHA224 ECDSA";
        when [0x04, 0x01]; "rsa_pkcs1_sha256";
        when [0x04, 0x02]; "SHA256 DSA";
        when [0x04, 0x03]; "ecdsa_secp256r1_sha256";
        when [0x05, 0x01]; "rsa_pkcs1_sha384";
        when [0x05, 0x02]; "SHA384 DSA";
        when [0x05, 0x03]; "ecdsa_secp384r1_sha384";
        when [0x06, 0x01]; "rsa_pkcs1_sha512";
        when [0x06, 0x02]; "SHA512 DSA";
        when [0x06, 0x03]; "ecdsa_secp521r1_sha512";
        when [0x08, 0x04]; "rsa_pss_rsae_sha256";
        when [0x08, 0x05]; "rsa_pss_rsae_sha384";
        when [0x08, 0x06]; "rsa_pss_rsae_sha512";
        when [0x08, 0x07]; "ed25519";
        when [0x08, 0x08]; "ed448";
        when [0x08, 0x09]; "rsa_pss_pss_sha256";
        when [0x08, 0x0A]; "rsa_pss_pss_sha384";
        when [0x08, 0x0B]; "rsa_pss_pss_sha512";
        else
          "Unknown (#{data[cur_ptr, 2]})"
      end
      cur_ptr += 2
    end
    to_ret
  end

  def parse_status_request(data)
    type = data[0]
    case type
      when TLSTypes::ExtenData::StatusRequest::OCSP
        return "OCSP"
      else
        return "Unknown #{type}"
    end
  end

  def parse_supported_groups(data)
    length = data[0]*256 + data[1]
    return if data.length != length+2
    cur_ptr = 2
    to_ret = []
    while cur_ptr < data.length do
      to_ret << case data[cur_ptr, 2]
        when [0x00, 0x01]; "sect163k1";
        when [0x00, 0x02]; "sect163r1";
        when [0x00, 0x03]; "sect163r2";
        when [0x00, 0x04]; "sect193r1";
        when [0x00, 0x05]; "sect193r2";
        when [0x00, 0x06]; "sect233k1";
        when [0x00, 0x07]; "sect233r1";
        when [0x00, 0x08]; "sect239k1";
        when [0x00, 0x09]; "sect283k1";
        when [0x00, 0x0a]; "sect283r1";
        when [0x00, 0x0b]; "sect409k1";
        when [0x00, 0x0c]; "sect409r1";
        when [0x00, 0x0d]; "sect571k1";
        when [0x00, 0x0e]; "sect571r1";
        when [0x00, 0x0f]; "secp160k1";
        when [0x00, 0x10]; "secp160r1";
        when [0x00, 0x11]; "secp160r2";
        when [0x00, 0x12]; "secp192k1";
        when [0x00, 0x13]; "secp192r1";
        when [0x00, 0x14]; "secp224k1";
        when [0x00, 0x15]; "secp224r1";
        when [0x00, 0x16]; "secp256k1";
        when [0x00, 0x17]; "secp256r1";
        when [0x00, 0x18]; "secp384r1";
        when [0x00, 0x19]; "secp521r1";
        when [0x00, 0x1a]; "brainpoolP256r1";
        when [0x00, 0x1b]; "brainpoolP384r1";
        when [0x00, 0x1c]; "brainpoolP512r1";
        when [0x00, 0x1d]; "x25519";
        when [0x00, 0x1e]; "x448";
        else
          "Unknown (#{data[cur_ptr, 2]})"
      end
      cur_ptr += 2
    end
    to_ret
  end

  def parse_supported_versions(data)
    length = data[0]
    return [] if length+1!=data.length
    cur_ptr = 1
    to_ret = []
    while cur_ptr < data.length do
      to_ret << data[cur_ptr, 2]
      cur_ptr += 2
    end
    to_ret
  end

  def parse_servername(data)
    total_length = data[0]*256 + data[1]
    cur_ptr = 2
    return if cur_ptr + total_length != data.length
    to_ret = []
    while cur_ptr<data.length do
      type = data[cur_ptr]
      length = data[cur_ptr+1]*256 + data[cur_ptr+2]
      cur_ptr += 3
      if type == TLSTypes::ExtenData::ServerName::HostName then
        to_ret << data[cur_ptr, length].pack('C*')
      end
      cur_ptr += length
    end
    to_ret
  end

  def inspect
    str  = "#<#{self.class.name}:"
    #str += " v1.2" if @innververs == 0x0303
    #str += " Cipher:"
    @ciphersuites.each do |c|
      #str += " 0x%02X%02X" % c
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

    if @extensions.select { |x| x[:type] == TLSTypes::Extensions::RenegotiationInfo }.empty? && !@cipersuites.include?([0x00, 0xFF]) then
      str += " ###### NO RENEGOTIATION INFO ####### "
    end

    str += ">"
    return str
  end

  def initialize(data)
    raise TLSClientHelloError unless data[0] == TLSTypes::RecordType::HANDSHAKE
    @outervers = data[1, 2]
    @outerlen  = data[3]*256 + data[4]
    raise TLSClientHelloError, 'Not a TLS Client Hello' unless data[5] == TLSTypes::HandshakeType::CLIENTHELLO
    @innerlen = data[6]*256*256 + data[7]*256 + data[8]
    @innervers = data[9, 2]
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
    @byexten = {}
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
      @byexten[exten[:type]] = exten[:data]
    end
  end
end
