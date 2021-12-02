# frozen_string_literal: true

require 'digest'
require_relative './tlsciphersuites'
require_relative './fingerprint'
require_relative './errors'

# Container for all TLS related constants
module TLSTypes
  # Supported TLS Record Types.
  # @todo Currently this is only the Handshake record. In future it might be a good Idea to also support other types.
  module RecordType
    # TLS ChangeCipherSpec Record
    CHANGE_CIPHER_SPEC = 0x14
    # TLS Alert Record
    ALERT              = 0x15
    # TLS Handshake Record
    HANDSHAKE          = 0x16
    # TLS ApplicationData Record
    APPLICATION_DATA   = 0x17
  end

  # Supported Handshake Types
  module HandshakeType
    # TLS Handshake ClientHello
    CLIENTHELLO         =  1
    # TLS Handshake ServerHello
    SERVERHELLO         =  2
    # TLS Handshake Certificate
    CERTIFICATE         = 11
    # TLS Handshake ServerKeyExchange
    # Used in DHE/ECDHE
    SERVERKEYEXCHANGE   = 12
    # TLS Handshake CertificateRequest
    # Used for requesting a Certificate (sent e.g. by the Server for requesting a Client Certificate)
    CERTIFICATE_REQUEST = 13
    # TLS Handshake ServerHelloDone
    SERVERHELLODONE     = 14
    # TLS Handshake ClientKeyExchange
    CLIENTKEYEXCHANGE   = 16
    # TLS Handshake CertificateStatus
    # Used in OCSP-Stapling responses
    CERTIFICATESTATUS   = 22
  end

  # TLS Alert Types
  module Alerts
    # TLS Alert Close Notify
    CLOSE_NOTIFY            = 0x00
    # TLS Alert Unexpected Message
    UNEXPECTED_MESSAGE      = 0x0a
    # TLS Alert Handshake Failure
    HANDSHAKE_FAILURE       = 0x28
    # TLS Alert No Certificate
    NO_CERTIFICATE          = 0x29
    # TLS Alert Bad Certificate
    BAD_CERTIFICATE         = 0x2A
    # TLS Alert Unsupported Certificate
    UNSUPPORTED_CERTIFICATE = 0x2B
    # TLS Alert Certificate Revoked
    CERTIFICATE_REVOKED     = 0x2C
    # TLS Alert Certificate Expired
    CERTIFICATE_EXPIRED     = 0x2D
    # TLS Alert Certificate Unknown
    CERTIFICATE_UNKNOWN     = 0x2E
    # TLS Alert Illegal Parameter
    ILLEGAL_PARAMETER       = 0x2F
    # TLS Alert Unknown CA
    UNKNOWN_CA              = 0x30
    # TLS Alert Access Denied
    ACCESS_DENIED           = 0x31
    # TLS Alert Decode Error
    DECODE_ERROR            = 0x32
    # TLS Alert Decrypt Error
    DECRYPT_ERROR           = 0x33
    # TLS Alert Protocol Version
    PROTOCOL_VERSION        = 0x46
    # TLS Alert Internal Error
    INTERNAL_ERROR          = 0x50

    # Get alert name by the given code
    # @param code [Byte] Code of the Alert
    # @return [String] Name of the Alert, or "UNKNOWN_ALERT_<num>" if Alert is unknown
    def self.get_alert_name_by_code(code)
      Alerts.constants.each do |const|
        next if Alerts.const_get(const) != code

        return const.to_s
      end
      "UNKNOWN_ALERT_#{code}"
    end
  end

  # Supported TLS Extensions
  # https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
  module Extensions
    # TLS Extension Server Name
    # Also known as Server Name Indication (SNI)
    # Defined in RFC6066
    SERVER_NAME             =     0
    # TLS Extension Status Request
    # Used for OCSP
    # Defined in RFC6066
    STATUS_REQUEST          =     5
    # TLS Extension Supported Groups
    # Previous known as Elliptic Curves
    # Indicates support for specific elliptic curves for ECDHE exchange
    # and specific FiniteField DH Groups
    # Defined in RFC8422/RFC7919
    SUPPORTED_GROUPS        =    10
    # TLS Extension EC Point Formats
    # Defined in RFC8422
    EC_POINT_FORMATS        =    11
    # TLS Extension SignatureAlgorithms
    # Used in TLS>=v1.2 for used Signature Algorithms for DH Parameters
    # Defined in RFC8446
    SIGNATURE_ALGORITHMS    =    13
    # TLS Extension Heartbeat
    # Defined in RFC6520
    HEARTBEAT               =    15
    # TLS Extension Signed Certificate Timestamp
    # Defined in RFC6962
    SIGNED_CERT_TIMESTAMP   =    18
    # TLS Extension Encrypt then HMAC
    # Defined in RFC7366
    ENCRYPT_THEN_HMAC       =    22
    # TLS Extension Extended Master Secret
    # Defined in RFC 7627
    EXTENDED_MASTER_SECRET  =    23
    # TLS Extension Session Ticket
    # Defined in RFC5077/RFC8447
    SESSION_TICKET          =    35
    # TLS Extension Supported Versions
    # Used to indicate TLSv1.3 while maintaining the TLSv1.2 Handshake format
    # Defined in RFC8446
    SUPPORTED_VERSIONS      =    43
    # TLS Extension PSK Key Exchange Modes
    # Defined in RFC8446
    PSK_KEY_EXCHANGE_MODES  =    45
    # TLS Extension KeyShare
    # Used in TLSv1.3 to share (EC)DH Parameters in the Client-/Server-Hello Messages
    # Defined in RFC8446
    KEY_SHARE               =    51
    # TLS Extension Renegotiation Info
    # Indicates Support for Secure Renegotiation
    # May be used in ServerHello Extensions even if not included in the ClientHello extensions, if the client indicated support via SCSV
    # Defined in RFC5746
    RENEGOTIATION_INFO      = 65281

    # Get the extension name by the given code
    # @param code [Integer] Code of the Extension
    # @return [String] Name of the Extension, or "UNKNOWN_EXTENSION_<num>" if Extension is unknown
    def self.get_extension_name_by_code(code)
      Extensions.constants.each do |const|
        next if Extensions.const_get(const) != code

        return const.to_s
      end
      "UNKNOWN_EXTENSION_#{code}"
    end
  end

  # TLS Compression methods
  module Compression
    # No compression
    NULL = 0

    # DEFLATE compression
    # https://datatracker.ietf.org/doc/html/rfc3749
    DEFLATE = 1

    # LZS compression
    # https://datatracker.ietf.org/doc/html/rfc3943
    LZS = 64

    # Get the compression name by the given code
    # @param code [Integer] Code of the Compression
    # @return [String] Name of the Compression, or "UNKNOWN_COMPRESSION_<num>" if Compression is unknown
    def self.get_compression_name_by_code(code)
      Compression.constants.each do |const|
        next if Compression.const_get(const) != code

        return const.to_s
      end
      "UNKNOWN_COMPRESSION_#{code}"
    end
  end

  # Container for all Extensions constants
  module ExtenData
    # Constants for Server Name Indication. Currently only HOST_NAME.
    module ServerName
      # SNI HostName
      HOST_NAME = 0
    end

    # Constants for Status Request. Currently only OCSP is specified
    module StatusRequest
      # StatusRequest OCSP
      OCSP = 1
    end
  end
end

# Class for parsing the TLS Client Hello
class TLSClientHello

  # [Integer] Length of inner TLS Data (in this case TLS Client Hello)
  attr_reader :innerlen
  # [Array] Version of the TLS Client Hello as Array of two bytes (e.g. [0x03,0x04])
  # Might differ from Outer TLS Version, especially for TLSv1.3
  attr_reader :innervers
  # [Array] Client Random as Array of 32 Bytes.
  attr_reader :random
  # [Array] Session ID as Array of Bytes. May be an empty array
  attr_reader :sessionid
  # [Array] Included Cipher Suites as Array of Array of Bytes (e.g. [[0x00,0x01],[0x00,0xFF]])
  attr_reader :ciphersuites
  # [Array] Supported Compression methods as Array of Bytes.
  attr_reader :compression
  # [Array] Included TLS Extensions as Array of Arrays of Bytes
  attr_reader :extensions

  # Convert parsed TLS Client Hello to Hash
  # @return Hash to insert in Elasticsearch
  def to_h
    to_ret = {}
    to_ret[:version] = case @innervers
                       when [0x03, 0x03]
                         'TLSv1.2'
                       when [0x03, 0x02]
                         'TLSv1.1'
                       when [0x03, 0x01]
                         'TLSv1.0'
                       else
                         'Unknown'
                       end

    to_ret[:compression] = {}
    to_ret[:compression][:order] = @compression.map(&:to_s).join(' ')
    to_ret[:compression][:names] = @compression.map { |x| TLSTypes::Compression.get_compression_name_by_code(x) }

    to_ret[:all_extensions] = []
    to_ret[:extensionorder] = ''
    @extensions.each do |exten|
      exten_s = TLSTypes::Extensions.get_extension_name_by_code(exten[:type])
      to_ret[:all_extensions] << exten_s
    end
    to_ret[:extensionorder] = to_ret[:all_extensions].join ' '

    to_ret[:renegotion] = @ciphersuites.include?([0x00, 0xFF]) || !!@byexten[TLSTypes::Extensions::RENEGOTIATION_INFO]
    if @byexten[TLSTypes::Extensions::SERVER_NAME]
      to_ret[:servername] = parse_servername(@byexten[TLSTypes::Extensions::SERVER_NAME])
    end
    to_ret[:extendedmastersecret] = !!@byexten[TLSTypes::Extensions::EXTENDED_MASTER_SECRET]
    if @byexten[TLSTypes::Extensions::SUPPORTED_VERSIONS]
      ver = parse_supported_versions(@byexten[TLSTypes::Extensions::SUPPORTED_VERSIONS])
      to_ret[:version] = 'TLSv1.3' if ver.include? [0x03, 0x04]
    end
    to_ret[:supportedgroups] = if @byexten[TLSTypes::Extensions::SUPPORTED_GROUPS]
                                 parse_supported_groups(@byexten[TLSTypes::Extensions::SUPPORTED_GROUPS])
                               else
                                 []
                               end
    to_ret[:statusrequest] = if @byexten[TLSTypes::Extensions::STATUS_REQUEST]
                               parse_status_request(@byexten[TLSTypes::Extensions::STATUS_REQUEST])
                             else
                               []
                             end
    to_ret[:signaturealgorithms] = if @byexten[TLSTypes::Extensions::SIGNATURE_ALGORITHMS]
                                     parse_signature_algorithms(@byexten[TLSTypes::Extensions::SIGNATURE_ALGORITHMS])
                                   else
                                     []
                                   end
    to_ret[:ciphersuites] = @ciphersuites.map { |c| '0x%02X%02X' % c }
    to_ret[:cipherdata] = {}
    cdata = TLSCipherSuite.new(@ciphersuites)
    to_ret[:cipherdata][:export] = cdata.includes_export?
    to_ret[:cipherdata][:broken] = cdata.includes_broken?
    to_ret[:cipherdata][:outdated] = cdata.includes_old_outdated?
    to_ret[:cipherdata][:min_sec_lvl] = cdata.get_min_sec_level
    to_ret[:cipherdata][:max_sec_lvl] = cdata.get_max_sec_level
    to_ret[:cipherdata][:all_keyx] = cdata.all_keyx
    to_ret[:cipherdata][:all_auth] = cdata.all_auth
    to_ret[:cipherdata][:all_encr] = cdata.all_encr
    to_ret[:cipherdata][:all_mac] = cdata.all_mac
    to_ret[:cipherdata][:all_keyx_list] = to_ret[:cipherdata][:all_keyx].sort.join(' ')
    to_ret[:cipherdata][:all_auth_list] = to_ret[:cipherdata][:all_auth].sort.join(' ')
    to_ret[:cipherdata][:all_encr_list] = to_ret[:cipherdata][:all_encr].sort.join(' ')
    to_ret[:cipherdata][:all_mac_list]  = to_ret[:cipherdata][:all_mac].sort.join(' ')
    to_ret[:cipherdata][:pfs_avail] = cdata.pfs_avail?
    to_ret[:cipherdata][:only_pfs] = cdata.only_pfs?
    to_ret[:cipherdata][:anull] = cdata.anull_present?
    to_ret[:cipherdata][:enull] = cdata.enull_present?
    to_ret[:cipherdata][:rc4] = cdata.rc4_present?
    to_ret[:cipherdata][:tripledes] = cdata.tripledes_present?
    to_ret[:cipherdata][:des] = cdata.des_present?
    to_ret[:cipherdata][:humanreadable] = cdata.humanreadable
    to_ret[:cipherdata][:cipherset] = cdata.cipherset
    to_ret[:cipherdata][:ciperset_length] = cdata.set_length
    to_ret[:cipherdata][:cipherset_length_noscsv] = cdata.set_length_noscsv

    to_ret[:cipherdata][:supported_group_set] = to_ret[:supportedgroups].join('+') || ''
    to_ret[:cipherdata][:signature_algorithm_set] = to_ret[:signaturealgorithms].join('+') || ''

    to_ret[:cipherdata][:supported_group_set] ||= ''
    to_ret[:cipherdata][:signature_algorithm_set] ||= ''

    to_ret[:fingerprinting] = {}

    to_ret[:fingerprinting][:v2] = Digest::SHA2.hexdigest(
      to_ret[:version] + '|' +
        to_ret[:cipherdata][:cipherset] + '|' +
        to_ret[:cipherdata][:supported_group_set] + '|' +
        to_ret[:cipherdata][:signature_algorithm_set] + '|' +
        ((to_ret[:statusrequest].nil? || to_ret[:statusrequest] == []) ? 'False' : to_ret[:statusrequest]) + '|' +
        (to_ret[:renegotiation] ? 'True' : 'False') + '|' +
        (to_ret[:extendedmastersecret] ? 'True' : 'False'))

    to_ret[:fingerprinting][:osdetails] = Fingerprint.to_h(to_ret[:fingerprinting][:v2])

    to_ret
  end

  # Parses SignatureAlgorithms Extension
  # @param data Extension Data as Byte Array
  # @return Parsed Extension content
  def parse_signature_algorithms(data)
    length = data[0] * 256 + data[1]
    return if data.length != length + 2

    cur_ptr = 2
    to_ret = []
    while cur_ptr < data.length do
      algo = TLSSignatureScheme.by_arr(data[cur_ptr, 2])
      to_ret << if algo.nil?
                  "Unknown (#{data[cur_ptr, 2]})"
                else
                  algo[:name]
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
      'OCSP'
    else
      "Unknown #{type}"
    end
  end

  # Parses SupportedGroups Extension
  # @param data Extension Data as Byte Array
  # @return Parsed Extension content
  def parse_supported_groups(data)
    length = data[0] * 256 + data[1]
    return if data.length != length+2

    cur_ptr = 2
    to_ret = []
    while cur_ptr < data.length do
      algo = TLSSupportedGroups.by_arr(data[cur_ptr, 2])
      to_ret << if algo.nil?
                  "Unknown (#{data[cur_ptr, 2]})"
                else
                  algo[:name]
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
      to_ret << data[cur_ptr, length].pack('C*') if type == TLSTypes::ExtenData::ServerName::HOST_NAME
      cur_ptr += length
    end
    to_ret
  end

  # Inspect the current Client Hello
  # @return [String] description of the Client Hello
  def inspect
    str = "#<#{self.class.name}:"
    # str += " v1.2" if @innververs == 0x0303
    # str += " Cipher:"
    # @ciphersuites.each do |c|
    #   str += " 0x%02X%02X" % c
    # end
    @extensions.each do |e|
      case e[:type]
      when TLSTypes::Extensions::SERVER_NAME
        str += ' ServerName'
      when TLSTypes::Extensions::STATUS_REQUEST
        str += ' StatusRequest'
      when TLSTypes::Extensions::SUPPORTED_GROUPS
        str += ' SupportedGroups'
      when TLSTypes::Extensions::EC_POINT_FORMATS
        str += ' ECPointFormats'
      when TLSTypes::Extensions::SIGNATURE_ALGORITHMS
        str += ' SignatureAlgorithms'
      when TLSTypes::Extensions::HEARTBEAT
        str += ' Heartbeat'
      when TLSTypes::Extensions::SIGNED_CERT_TIMESTAMP
        str += ' SignedCertTimestamp'
      when TLSTypes::Extensions::ENCRYPT_THEN_HMAC
        str += ' EncryptThenHMAC'
      when TLSTypes::Extensions::EXTENDED_MASTER_SECRET
        str += ' ExtendedMasterSecret'
      when TLSTypes::Extensions::SESSION_TICKET
        str += ' SessionTicket'
      when TLSTypes::Extensions::SUPPORTED_VERSIONS
        str += ' SupportedVersions'
      when TLSTypes::Extensions::PSK_KEY_EXCHANGE_MODES
        str += ' PSKKeyExchangeModes'
      when TLSTypes::Extensions::KEY_SHARE
        str += ' KeyShare'
      when TLSTypes::Extensions::RENEGOTIATION_INFO
        str += ' RenegotiationInfo'
      else
        $stderr.puts "Unsupported TLS Extension #{e[:type]}"
      end
    end

    if @extensions.select { |x| x[:type] == TLSTypes::Extensions::RENEGOTIATION_INFO }.empty? &&
       !@ciphersuites.include?([0x00, 0xFF])
      str += ' ###### NO RENEGOTIATION INFO ####### '
    end

    "#{str}>"
  end

  # Parses TLS Client Hello and returns a new Instance of TLSClientHello
  # @param data Array of Bytes containing the Complete TLS Record
  # @raise TLSClientHelloError if any parsing error occurs
  # @return New Instance of TLSClientHello
  def initialize(data)
    raise TLSClientHelloError, 'Not a TLS Client Hello' unless data[0] == TLSTypes::HandshakeType::CLIENTHELLO

    @innerlen = data[1]*256*256 + data[2]*256 + data[3]
    @innervers = data[4, 2]
    @random = data[6, 32]
    cur_ptr = 38

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
