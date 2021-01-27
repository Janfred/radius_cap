require_relative './tlsciphersuites.rb'
require 'openssl'

# Error to be thrown whenever the parsing of the TLS Server Hello fails.
class TLSServerHelloError < StandardError
end

# Class for parsing the TLS Server Hello
class TLSServerHello

  include SemanticLogger::Loggable

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
  attr_reader :cert_data
  # Not yet used
  attr_reader :additional

  # Sets if the ServerHelloDone Record was captured.
  # This will be false until the Record was seen and remains false if it is
  # a session resumption.
  attr_reader :serverhellodone


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

    to_ret[:downgrade] = @downgrade || "None"

    to_ret[:all_extensions] = []
    to_ret[:extensionsorder] = ''
    @extensions.each do |exten|
      exten_s = TLSTypes::Extensions::get_extension_name_by_code(exten[:type])
      to_ret[:all_extensions] << exten_s
    end
    to_ret[:extensionsorder] = to_ret[:all_extensions].join ' '
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

    to_ret[:certificate] = {}
    to_ret[:certificate][:sent_chain_length] = @cert_data.length
    to_ret[:certificate][:public_trusted] = @public_trusted[:valid]

    if @public_trusted[:valid]
      to_ret[:certificate][:complete_public_chain_length] = @public_trusted[:chain].length
      to_ret[:certificate][:public_trust_anchor] = @public_trusted[:chain].last.subject.to_s
    else
      to_ret[:certificate][:complete_public_chain_length] = 0
      to_ret[:certificate][:public_trust_anchor] = "UNKNOWN"
    end

    index = 0
    to_ret[:certificate][:public_chain] = {}
    to_ret[:certificate][:public_chain][:array] = []
    to_ret[:certificate][:public_chain][:by_index] = {}
    @public_trusted[:chain].reverse.each do |c|
      to_ret[:certificate][:public_chain][:array] << c.subject.to_s
      to_ret[:certificate][:public_chain][:by_index][index] = c.subject.to_s
      index += 1
    end

    index = 0
    to_ret[:certificate][:additional_chain] = {}
    to_ret[:certificate][:additional_chain][:array] = []
    to_ret[:certificate][:additional_chain][:by_index] = {}
    @additional_trusted[:chain].reverse.each do |c|
      to_ret[:certificate][:additional_chain][:array] << c.subject.to_s
      to_ret[:certificate][:additional_chain][:by_index][index] = c.subject.to_s
      index += 1
    end

    to_ret[:certificate][:additional_trusted] = @additional_trusted[:valid]
    to_ret[:certificate][:complete_additional_chain_length] = @additional_trusted[:chain].length
    to_ret[:certificate][:additional_trust_anchor] = @additional_trusted[:chain].last.subject.to_s unless @additional_trusted[:chain].last.nil?


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
  # @param data [Array<TLSHandshakeRecord>] Bytes from Server Hello until ServerHelloDone
  # @return New Instance of TLSServerHello
  def initialize(data)
    @ocsp_included = false
    @additional = {}
    @serverhellodone = false
    @cert_data = []
    @public_trusted = {}
    @public_trusted[:chain] = []
    @additional_trusted = {}
    @additional_trusted[:chain] = []
    data.each do |cur_record|
      if cur_record.is_a? TLSChangeCipherSpecRecord
        # If this is the case, this probably is a Session resumption.
        # We have to abort here, because the server will continue with encrypted
        # data, but we have to save the fact that the session was resumed.
        if @serverhellodone
          # The ChangeCipherSpec came after the ServerHelloDone, so it is
          # normal operation. We can just break and do nothing more.
          break
        else
          # If the ChangeCipherSpec is before we capture the ServerHelloDone
          # it probably is a Session Resumption.
          # We save that before we break.
          logger.info "Seen a probable Session Resumption"
          @additional[:resumption] = true
          break
        end
      end
      raise ProtocolStackError.new 'The Record in the TLS Server Hello was not a TLSHandshakeRecord' unless cur_record.is_a? TLSHandshakeRecord
      raise ProtocolStackError.new 'The Handshake type was not set' if cur_record.handshake_type.nil?

      cur_data = cur_record.data
      type = cur_record.handshake_type
      length = cur_data[1] * 256 * 256 + cur_data[2] * 256 + cur_data[3]

      case type
      when TLSTypes::HandshakeType::SERVERHELLO
        logger.trace 'TLS ServerHello SERVERHELLO'
        parse_serverhello cur_data[4, length]
      when TLSTypes::HandshakeType::CERTIFICATE
        logger.trace 'TLS ServerHello Certificate'
        parse_certificate cur_data[4, length]
      when TLSTypes::HandshakeType::SERVERKEYEXCHANGE
        logger.trace 'TLS ServerHello SERVERKEYEXCHANGE'
        parse_serverkeyexchange cur_data[4, length]
      when TLSTypes::HandshakeType::SERVERHELLODONE
        logger.trace 'TLS ServerHello SERVERHELLODONE'
        parse_serverhellodone cur_data[4, length]
      when TLSTypes::HandshakeType::CERTIFICATESTATUS
        logger.trace 'TLS ServerHello CERTIFICATESTATUS'
        parse_certificatestatus cur_data[4, length]
      when TLSTypes::HandshakeType::CERTIFICATE_REQUEST
        logger.trace 'TLS ServerHello CERTIFICATE_REQUEST'
        parse_certificaterequest cur_data[4, length]
      else
        logger.warn "Unknown TLS Handshake Type #{type} for the Server Hello"
      end
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

    if @random[24, 8] == [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
      @downgrade = "DOWNGRD1"
    elsif @random[24, 8] == [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]
      @downgrade = "DOWNGRD0"
    end

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
      cur_cert = data[cur_ptr, this_length]

      cur_cert_data = OpenSSL::X509::Certificate.new cur_cert.pack('C*')

      logger.debug 'Cert data ' + cur_cert_data.inspect

      @certificates ||= []
      @certificates << cur_cert
      @cert_data ||= []
      @cert_data << cur_cert_data
      cur_ptr += this_length
    end

    if @cert_data.length > 0
      server_cert = @cert_data.first
      chain = @cert_data[1..-1]

      TLSCertStoreHelper.save_server_cert(server_cert)

      chain.each do |c|
        if TLSCertStoreHelper.check_trust_anchor(c)
          TLSCertStoreHelper.add_trust_anchor(c)
        end
        TLSCertStoreHelper.add_known_intermediate(c)
      end

      @public_trusted = TLSCertStoreHelper.check_public_trust(server_cert, chain)
      logger.trace 'Public Cert Result: ' + @public_trusted.inspect
      @additional_trusted = TLSCertStoreHelper.check_additional_trust(server_cert, chain)
      logger.trace 'Additional Cert Result: ' + @additional_trusted.inspect
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

  # Parses Certificate Request
  # @todo This is just a stub, it should be extended.
  def parse_certificaterequest(dat)
    nil
  end

  # Parses ServerHelloDone. This just sents the serverhellodone to true
  # @return nil
  def parse_serverhellodone(data)
    @serverhellodone = true
    # Nothing to do.
    nil
  end
end

# Class for Storing the seen TLS Certs
class TLSCertStoreHelper
  include Singleton
  include SemanticLogger::Loggable


  attr_reader :trusted_cert_store
  attr_reader :additional_cert_store

  def initialize
    @trusted_cert_store = OpenSSL::X509::Store.new
    @trusted_cert_store.set_default_paths

    @additional_cert_store = OpenSSL::X509::Store.new
    @additional_cert_store.set_default_paths

    priv_add_known_intermediates
  end

  # Add the seen_certs to the additional cert store
  def priv_add_known_intermediates
    @additional_cert_store.add_path('seen_certs')
  end

  # Convert original subject name to a posix compatible file name.
  # Replaces slashes with Paragraph, everything else with underscore
  # @param orig_name [String] original subject
  # @return [String] an escaped file name
  # @private
  def subj_to_filename(orig_name)
    to_return = orig_name
    to_return.gsub!(/\//,'§')
    to_return.gsub!(/[^0-9a-zA-Z. _=§-]/, '_')

    to_return
  end

  # Save a server certicicate to the certificate store
  # @param cert [OpenSSL::X509::Certificate] certificate to save
  def self.save_server_cert(cert)
    TLSCertStoreHelper.instance.priv_add_cert(cert, false)
  end

  # Get the subject key identifier fo the certificate.
  # If the certificate contains multiple SubjectKeyIdentifier attributes the first one is returned,
  # if none is given the SHA2-Hash of the entire certificate (DER encoded) is returned.
  # @param cert [OpenSSL::X509::Certificate] certificate
  # @return [String] SubjectKeyIdentifier
  # @private
  def get_subj_key_identifier(cert)
    subject_key_identifier_exten = cert.extensions.select{|x| x.oid == "subjectKeyIdentifier"}
    if subject_key_identifier_exten.length < 1
      logger.warn "Found certificate without subjectKeyIdentifier. Using SHA-2 Hash of the certificate"
      return Digest::SHA2.hexdigest(cert.to_der).upcase
    elsif subject_key_identifier_exten.length == 1
      return subject_key_identifier_exten.first.value.gsub(/:/,'')
    else
      logger.warn "Found multiple subjectKeyIdentifier Extensions in X.509 Cert for #{cert.subject.to_s}"
      return subject_key_identifier_exten.first.value.gsub(/:/,'')
    end
  end

  # Private Function to add a cert to certificate store.
  # If this is an intermediate certificate, it is also stored in the additional cert store for future reference
  # @param cert [OpenSSL::X509::Certificate] certificate to save
  # @param intermediate [Boolean]
  def priv_add_cert(cert, intermediate=false)
    raise StandardError unless cert.is_a? OpenSSL::X509::Certificate
    issuer = cert.issuer.to_s
    cert_serial = cert.serial
    cert_name = cert.subject.to_s

    subject_key_identifier = get_subj_key_identifier(cert)

    authority_key_identifier_exten = cert.extensions.select{|x| x.oid == "authorityKeyIdentifier"}
    authority_key_identifier = ""
    if authority_key_identifier_exten.length == 0
      authority_key_identifier = "UNKNOWN"
    elsif authority_key_identifier_exten.length == 1
      authority_key_identifier = authority_key_identifier_exten.first.value
    else
      logger.warn "Found multiple authorityKeyIdentifier Extensions in X.509 Cert for #{cert_name}"
      authority_key_identifier = authority_key_identifier_exten.first.value
    end

    match = authority_key_identifier.match /^keyid:(.*)$/
    if match
      authority_key_identifier = match[1].gsub /:/, ''
    else
      authority_key_identifier = "UNKNOWN"
    end

    logger.trace "Issuer: #{issuer} | Serial: #{cert_serial} | Cert Name: #{cert_name}"

    issuer_path = authority_key_identifier
    cert_path = subject_key_identifier

    unless File.directory? File.join('seen_certs', issuer_path)
      Dir.mkdir(File.join('seen_certs', issuer_path))
    end
    unless File.exists? File.join('seen_certs', issuer_path, cert_path)
      File.write File.join('seen_certs', issuer_path, cert_path), cert.to_pem
      @additional_cert_store.add_cert(cert) if intermediate
    end
  end

  # Add a possible Trust anchor to the Cert store
  # @param cert [OpenSSL::X509::Certificate] Certificate to add
  def self.add_trust_anchor(cert)
    TLSCertStoreHelper.instance.priv_add_trust_anchor(cert)
  end

  # Private helper function to add trust anchor
  # @param cert [OpenSSL::X509::Certificate] Certificate to add
  # @private
  def priv_add_trust_anchor(cert)
    raise StandardError unless cert.is_a? OpenSSL::X509::Certificate
    certname = get_subj_key_identifier(cert) + '.pem'
    unless File.exists? File.join('seen_certs', certname)
      File.write(File.join('seen_certs', certname), cert.to_pem)
      @additional_cert_store.add_cert(cert)
    end
  end

  # Add an intermediate certificate to the cert store
  # @param cert [OpenSSL::X509::Certificate] certificate to add
  def self.add_known_intermediate(cert)
    TLSCertStoreHelper.instance.priv_add_cert(cert, true)
  end

  # Check if a given certificate may be a trust ancor (based on same Issuer and Subject)
  # @param cert [OpenSSL::X509::Certificate] Certificate to check
  # @return [Boolean] if the given Cert may be a trust anchor
  def self.check_trust_anchor(cert)
    raise StandardError unless cert.is_a? OpenSSL::X509::Certificate
    logger.trace "Checking #{cert.issuer.to_s} against #{cert.subject.to_s}"
    return cert.issuer.eql? cert.subject
  end

  # Check a given Cert with a given Certificate Chain against the public trust store
  # @param cert [OpenSSL::X509::Certificate] Certificate to check
  # @param chain [Array<OpenSSL::X509::Certificate] Chain of Certificates as Array of Certificates
  # @return [Hash]
  #    * :valid [Boolean] if the certificate is trusted
  #    * :chain [Array] Certificate Chain
  def self.check_public_trust(cert, chain)
    certstore = TLSCertStoreHelper.instance.trusted_cert_store
    raise StandardError unless certstore.is_a? OpenSSL::X509::Store
    to_return = {}
    to_return[:valid] = certstore.verify(cert, chain)
    to_return[:chain] = certstore.chain

    to_return
  end
  # Check a given Cert with a given certificate chain against the additional trust store
  # @param cert [OpenSSL::X509::Certificate] Certificate to check
  # @param chain [Array<OpenSSL::X509::Certificate] Chain of Certificates as Array of Certificates
  # @return [Hash]
  #    * :valid [Boolean] if the certificate is trusted
  #    * :chain [Array] Certificate Chain
  def self.check_additional_trust(cert, chain)
    certstore = TLSCertStoreHelper.instance.additional_cert_store
    raise StandardError unless certstore.is_a? OpenSSL::X509::Store
    to_return = {}
    to_return[:valid] = certstore.verify(cert, chain)
    to_return[:chain] = certstore.chain

    to_return
  end
end