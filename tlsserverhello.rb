require './tlsciphersuites.rb'

# Error to be thrown whenever the parsing of the TLS Server Hello fails.
class TLSServerHelloError < StandardError
end

# Class for parsing the TLS Server Hello
class TLSServerHello
  # [Array] Outer TLS Version (TLS Record Version) as Array of two bytes (e.g. [0x03,0x01])
  attr_reader :outervers
  # [Array] Version of the TLS Server Hello as Array of two bytes (e.g. [0x03,0x03])
  # Might differ from Outer TLS Version, especially for TLSv1.3
  attr_reader :innervers
  # [Array] Server Random as Array of 32 Bytes.
  # This might also include Information about Downgrade (e.g. the ASCII DOWNGRD followed by 0x00 or 0x01 if the server supports a higher version then the client requested)
  attr_reader :random
  # [Array] Session ID as Array of Bytes. Might be an empty array if no Session ID is present.
  attr_reader :sessionid
  # [Array] Chosen Cipher as Array of two bytes (e.g. [0xC0,0x09])
  attr_reader :cipher
  # [Byte] Chosen Compression
  attr_reader :compression
  # [Array] Included Extensions as Array of Arrays of Bytes
  attr_reader :extensions
  # [Array] Sent Certificates as Array of Arrays of Bytes
  attr_reader :certificates
  # Not yet used
  attr_reader :additional

  # Converts parsed TLS Server Hello to Hash
  # @todo Lacks support for TLSv1.3
  # @return Hash to insert in Elasticsearch
  def to_h
    to_ret = {}
    to_ret[:version] = case @innervers
      when [0x03, 0x03]; "TLSv1.2";
      when [0x03, 0x02]; "TLSv1.1";
      when [0x03, 0x01]; "TLSv1.0";
      else
        "Unknown"
    end
    to_ret[:renegotiation] = !!@byexten[TLSTypes::Extensions::RENEGOTIATION_INFO]
    to_ret[:extendedmastersecret] = !!@byexten[TLSTypes::Extensions::EXTENDED_MASTER_SECRET]
    if @byexten[TLSTypes::Extensions::SUPPORTED_VERSIONS]
      to_ret[:version] = "TLSv1.3" if @byexten[TLSTypes::Extensions::SUPPORTED_VERSIONS] == [0x03, 0x04]
    end
    to_ret[:cipher] = "0x%02X%02X" % @cipher
    to_ret[:cipherdata] = {}
    cdata = TLSCipherSuite.by_arr(@cipher)
    to_ret[:cipherdata]["FS"] = cdata[:pfs]
    to_ret[:cipherdata]["auth"] = cdata[:auth]
    to_ret[:cipherdata]["encry"] = cdata[:encryption]
    to_ret[:cipherdata]["keyx"] = cdata[:keyxchange]
    to_ret[:cipherdata]["name"] = cdata[:name]
    to_ret[:stapling] = @ocsp_included
    to_ret[:keyexchange] = @keyexchange.to_h if @keyexchange
    # If no keyexchange is present, set to None to distinguish between not captured (before this change) and captured, but not existent
    to_ret[:keyexchange] ||= [sig_scheme: "None", curve_name: "None"]
    to_ret
  end


  def inspect
    str  = "#<#{self.class.name}:"
    #str += " v1.2" if @innververs == 0x0303
    #str += " Cipher:"
    #str += " 0x%02X%02X" % @cipher
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
    str + ">"
  end

  # Parses complete ServerHello and returns a new Instance
  # @param data [Array] Bytes from Server Hello until ServerHelloDone
  # @return New Instance of TLSServerHello
  def initialize(data)
    @ocsp_included = false
    cur_ptr = 0
    while cur_ptr < data.length do
      outertype = data[cur_ptr]
      @outervers = data[cur_ptr+1, 2]
      outerlength = data[cur_ptr+3]*256 + data[cur_ptr+4]
      cur_ptr += 5
      type = data[cur_ptr]
      length = data[cur_ptr+1]*256*256 + data[cur_ptr+2]*256 + data[cur_ptr+3]
      if outerlength-length != 4
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
        when TLSTypes::HandshakeType::CERTIFICATESTATUS
          parse_certificatestatus data[cur_ptr+4, length]
        else
          $stderr.puts "Unknown TLS Handshaketype #{type}"
      end
      cur_ptr += outerlength
    end
  end

  # Parses Server Hello
  # @param data [Array] Content of TLS Handshake Record SERVERHELLO
  # @todo Lacks support for TLSv1.3
  # @return nil
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
      exten[:data] = data[cur_ptr, exten[:length]]
      cur_ptr += exten[:length]
      @extensions << exten
      @byexten[exten[:type]] = exten[:data]
    end
    nil
  end

  # Parses Certificates to @certificates
  # @param data [Array] Content of TLS Handshake Record CERTIFICATE
  # @return nil
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
    nil
  end

  # Parses Server Key Exchange
  # @param data [Array] Content of TLS Handshake Record SERVERKEYEXCHANGE
  def parse_serverkeyexchange(data)
    # Not yet implemented
    @keyexchange = TLSServerKeyExchange.parse(data, @cipher, @innervers)
    nil
  end

  # Parses OCSP Response
  # @todo This is still a stub, here the type of OCSP Response should be parsed
  # @param data [Array] Content of TLS Handshake Record CERTIFICATESTATUS
  # @return nil
  def parse_certificatestatus(data)
    @ocsp_included = true
    nil
  end

  # Parses ServerHelloDone. This does nothing for now.
  # @todo Once the parsing is advancing, this might do some housekeeping or signalling
  # @return nil
  def parse_serverhellodone(data)
    # Nothing to do.
    nil
  end
end
