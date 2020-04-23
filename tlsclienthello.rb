require 'digest'
require './tlsciphersuites.rb'
require './fingerprint.rb'

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
    CERTIFICATESTATUS = 22
  end
  module Extensions
    SERVER_NAME             =     0
    STATUS_REQUEST          =     5
    SUPPORTED_GROUPS        =    10
    EC_POINT_FORMATS        =    11
    SIGNATURE_ALGORITHMS    =    13
    HEARTBEAT               =    15
    SIGNED_CERT_TIMESTAMP   =    18
    ENCRYPT_THEN_HMAC       =    22
    EXTENDED_MASTER_SECRET  =    23
    SESSION_TICKET          =    35
    SUPPORTED_VERSIONS      =    43
    PSK_KEY_EXCHANGE_MODES  =    45
    KEY_SHARE               =    51
    RENEGOTIATION_INFO      = 65281
  end
  module ExtenData
    module ServerName
      HOST_NAME = 0
    end
    module StatusRequest
      OCSP = 1
    end
  end
end

class TLSClientHello

  # Outer TLS Version (TLS Record Version)
  attr_reader :outervers
  # Length of the TLS Record
  attr_reader :outerlen
  # Length of inner TLS Data (in this case TLS Client Hello)
  attr_reader :innerlen
  # Version of the TLS Client Hello.
  # Might differ from Outer TLS Version, especially for TLSv1.3
  attr_reader :innervers
  # Client Random
  attr_reader :random
  # Session ID
  attr_reader :sessionid
  # [Array] Included Cipher Suites as Array of Array of Bytes (e.g. [[0x00,0x01],[0x00,0xFF]])
  attr_reader :ciphersuites
  # Supported Compression methods.
  attr_reader :compression
  # [Array] Included TLS Extensions
  attr_reader :extensions

  # Convert parsed TLS Client Hello to Hash
  # @return Hash to insert in Elasticsearch
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
    to_ret[:renegotion] = @ciphersuites.include?([0x00,0xFF]) || !!@byexten[TLSTypes::Extensions::RENEGOTIATION_INFO]
    to_ret[:servername] = parse_servername(@byexten[TLSTypes::Extensions::SERVER_NAME]) if @byexten[TLSTypes::Extensions::SERVER_NAME]
    to_ret[:extendedmastersecret] = !!@byexten[TLSTypes::Extensions::EXTENDED_MASTER_SECRET]
    if @byexten[TLSTypes::Extensions::SUPPORTED_VERSIONS]
      ver = parse_supported_versions(@byexten[TLSTypes::Extensions::SUPPORTED_VERSIONS])
      to_ret[:version] = "TLSv1.3" if ver.include? [0x03, 0x04]
    end
    if @byexten[TLSTypes::Extensions::SUPPORTED_GROUPS]
      to_ret[:supportedgroups] = parse_supported_groups(@byexten[TLSTypes::Extensions::SUPPORTED_GROUPS])
    else
      to_ret[:supportedgroups] = []
    end
    if @byexten[TLSTypes::Extensions::STATUS_REQUEST]
      to_ret[:statusrequest] = parse_status_request(@byexten[TLSTypes::Extensions::STATUS_REQUEST])
    else
      to_ret[:statusrequest] = []
    end
    if @byexten[TLSTypes::Extensions::SIGNATURE_ALGORITHMS]
      to_ret[:signaturealgorithms] = parse_signature_algorithms(@byexten[TLSTypes::Extensions::SIGNATURE_ALGORITHMS])
    else
      to_ret[:signaturealgorithms] = []
    end
    to_ret[:ciphersuites] = @ciphersuites.map {|c| "0x%02X%02X" % c}
    to_ret[:cipherdata] = {}
    cdata = TLSCipherSuite.new(@ciphersuites)
    to_ret[:cipherdata][:pfs_avail] = cdata.pfs_avail?
    to_ret[:cipherdata][:only_pfs] = cdata.only_pfs?
    to_ret[:cipherdata][:anull] = cdata.anull_present?
    to_ret[:cipherdata][:enull] = cdata.enull_present?
    to_ret[:cipherdata][:rc4] = cdata.rc4_present?
    to_ret[:cipherdata][:tripledes] = cdata.tripledes_present?
    to_ret[:cipherdata][:des] = cdata.des_present?
    to_ret[:cipherdata][:humanreadable] = cdata.humanreadable
    to_ret[:cipherdata][:cipherset] = cdata.cipherset

    to_ret[:cipherdata][:supported_group_set] = to_ret[:supportedgroups].join('+') || ""
    to_ret[:cipherdata][:signature_algorithm_set] = to_ret[:signaturealgorithms].join('+') || ""

    to_ret[:cipherdata][:supported_group_set] ||= ""
    to_ret[:cipherdata][:signature_algorithm_set] ||= ""

    to_ret[:fingerprinting] = {}

    to_ret[:fingerprinting][:v2] = Digest::SHA2.hexdigest(
      to_ret[:version] + "|" +
      to_ret[:cipherdata][:cipherset] + "|" +
      to_ret[:cipherdata][:supported_group_set] + "|" +
      to_ret[:cipherdata][:signature_algorithm_set] + "|" +
      ((to_ret[:statusrequest].nil? || to_ret[:statusrequest] == []) ? "False" : to_ret[:statusrequest]) + "|" +
      (to_ret[:renegotiation] ? "True" : "False") + "|" +
      (to_ret[:extendedmastersecret] ? "True" : "False") )

    to_ret[:fingerprinting][:osdetails] = Fingerprint.to_h(to_ret[:fingerprinting][:v2])

    to_ret
  end

  # Parses SignatureAlgorithms Extension
  # @param data Extension Data as Byte Array
  # @return Parsed Extension content
  def parse_signature_algorithms(data)
    length = data[0]*256 + data[1]
    return if data.length != length + 2
    cur_ptr = 2
    to_ret = []
    while cur_ptr < data.length do
      algo = TLSSignatureScheme.by_arr(data[cur_ptr, 2])
      if algo.nil?
        to_ret << "Unknown (#{data[cur_ptr, 2]})"
      else
        to_ret << algo[:name]
      end
      cur_ptr += 2
    end
    to_ret
  end

  # Parses StatusRequest (OCSP) Extension
  # @param data Extension Data as Byte Array
  # @return Parsed Extension content
  def parse_status_request(data)
    type = data[0]
    case type
      when TLSTypes::ExtenData::StatusRequest::OCSP
        return "OCSP"
      else
        return "Unknown #{type}"
    end
  end

  # Parses SupportedGroups Extension
  # @param data Extension Data as Byte Array
  # @return Parsed Extension content
  def parse_supported_groups(data)
    length = data[0]*256 + data[1]
    return if data.length != length+2
    cur_ptr = 2
    to_ret = []
    while cur_ptr < data.length do
      algo = TLSSupportedGroups.by_arr(data[cur_ptr, 2])
      if algo.nil?
        to_ret << "Unknown (#{data[cur_ptr, 2]})"
      else
        to_ret << algo[:name]
      end
      cur_ptr += 2
    end
    to_ret
  end

  # Parses SupportedVersion Extension
  # @param data Extension Data as Byte array
  # @return Parsed Extension content
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

  # Parses ServerName Extension (SNI)
  # @param data Extension Data as Byte Array
  # @return Parsed Extension content
  def parse_servername(data)
    total_length = data[0]*256 + data[1]
    cur_ptr = 2
    return if cur_ptr + total_length != data.length
    to_ret = []
    while cur_ptr<data.length do
      type = data[cur_ptr]
      length = data[cur_ptr+1]*256 + data[cur_ptr+2]
      cur_ptr += 3
      if type == TLSTypes::ExtenData::ServerName::HOST_NAME
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
        when TLSTypes::Extensions::SERVER_NAME
          str += " ServerName"
        when TLSTypes::Extensions::STATUS_REQUEST
          str += " StatusRequest"
        when TLSTypes::Extensions::SUPPORTED_GROUPS
          str += " SupportedGroups"
        when TLSTypes::Extensions::EC_POINT_FORMATS
          str += " ECPointFormats"
        when TLSTypes::Extensions::SIGNATURE_ALGORITHMS
          str += " SignatureAlgorithms"
        when TLSTypes::Extensions::HEARTBEAT
          str += " Heartbeat"
        when TLSTypes::Extensions::SIGNED_CERT_TIMESTAMP
          str += " SignedCertTimestamp"
        when TLSTypes::Extensions::ENCRYPT_THEN_HMAC
          str += " EncryptThenHMAC"
        when TLSTypes::Extensions::EXTENDED_MASTER_SECRET
          str += " ExtendedMasterSecret"
        when TLSTypes::Extensions::SESSION_TICKET
          str += " SessionTicket"
        when TLSTypes::Extensions::SUPPORTED_VERSIONS
          str += " SupportedVersions"
        when TLSTypes::Extensions::PSK_KEY_EXCHANGE_MODES
          str += " PSKKeyExchangeModes"
        when TLSTypes::Extensions::KEY_SHARE
          str += " KeyShare"
        when TLSTypes::Extensions::RENEGOTIATION_INFO
          str += " RenegotiationInfo"
        else
          $stderr.puts "Unsupported TLS Extension #{e[:type]}"
      end
    end

    if @extensions.select { |x| x[:type] == TLSTypes::Extensions::RENEGOTIATION_INFO }.empty? && !@ciphersuites.include?([0x00, 0xFF])
      str += " ###### NO RENEGOTIATION INFO ####### "
    end

    str + ">"
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

    if data.length <= cur_ptr
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
