# frozen_string_literal: true

require 'digest'

# Class for storing the seen TLS Certs without validating the server certificates
class TLSCertStoreOnly
  include Singleton
  include SemanticLogger::Loggable

  attr_reader :saved_certs

  def initialize
    @saved_certs = []
  end

  # Save certificates to file system
  # @param certs Array<OpenSSL::X509::Certificate> certificates to store
  # @return Array SHA256Sum of the certificate (PEM encoded) as hex string
  def self.save_certificates(certs)
    to_ret = []
    certs.each do |crt|
      next unless crt.is_a? OpenSSL::X509::Certificate

      pem = crt.to_pem
      hash = Digest::SHA2.hexdigest(pem)
      to_ret << hash
      next if instance.saved_certs.include? hash

      StackParser.instance.threadmutex.synchronize do
        instance.saved_certs << hash
        unless File.exist? File.join('seen_certs_raw', "#{hash}.pem")
          File.write(File.join('seen_certs_raw', "#{hash}.pem"), pem)
        end
      end
    end
    to_ret
  end
end

# Class for Storing the seen TLS Certs
class TLSCertStoreHelper
  include Singleton
  include SemanticLogger::Loggable

  attr_reader :trusted_cert_store, :additional_cert_store

  def initialize
    @trusted_cert_store = OpenSSL::X509::Store.new
    @trusted_cert_store.set_default_paths

    @additional_cert_store = OpenSSL::X509::Store.new
    @additional_cert_store.set_default_paths

    priv_add_known_intermediates
  end

  # Synchronize the given block for non-simultaneous file system access
  def sync(&block)
    StackParser.instance.threadmutex.synchronize(&block)
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
    to_return.gsub!(%r{/}, '§')
    to_return.gsub!(/[^\da-zA-Z. _=§-]/, '_')

    to_return
  end

  # Save a server certificate to the certificate store
  # @param cert [OpenSSL::X509::Certificate] certificate to save
  def self.save_server_cert(cert)
    TLSCertStoreHelper.instance.priv_add_cert(cert, intermediate: false)
  end

  # Get the subject key identifier fo the certificate.
  # If the certificate contains multiple SubjectKeyIdentifier attributes the first one is returned,
  # if none is given the SHA2-Hash of the entire certificate (DER encoded) is returned.
  # @param cert [OpenSSL::X509::Certificate] certificate
  # @return [String] SubjectKeyIdentifier
  # @private
  def get_subj_key_identifier(cert)
    subject_key_identifier_exten = cert.extensions.select { |x| x.oid == 'subjectKeyIdentifier' }
    if subject_key_identifier_exten.empty?
      logger.warn 'Found certificate without subjectKeyIdentifier. Using SHA-2 Hash of the certificate'
      Digest::SHA2.hexdigest(cert.to_der).upcase
    else
      first_exten = subject_key_identifier_exten.first
      return Digest::SHA2.hexdigest(cert.to_der).upcase unless first_exten.is_a? OpenSSL::X509::Extension

      if subject_key_identifier_exten.length > 1
        logger.warn "Found multiple subjectKeyIdentifier Extensions in X.509 Cert for #{cert.subject}"
      end
      first_exten.value.gsub(/:/, '')
    end
  end

  # Private Function to add a cert to certificate store.
  # If this is an intermediate certificate, it is also stored in the additional cert store for future reference
  # @param cert [OpenSSL::X509::Certificate] certificate to save
  # @param intermediate [Boolean]
  def priv_add_cert(cert, intermediate: false)
    raise StandardError unless cert.is_a? OpenSSL::X509::Certificate

    issuer = cert.issuer.to_s
    cert_serial = cert.serial
    cert_name = cert.subject.to_s

    subject_key_identifier = get_subj_key_identifier(cert)

    authority_key_identifier = get_auth_key_identifier(cert)

    logger.trace "Issuer: #{issuer} | Serial: #{cert_serial} | Cert Name: #{cert_name}"

    issuer_path = authority_key_identifier
    cert_path = subject_key_identifier

    sync do
      Dir.mkdir(File.join('seen_certs', issuer_path)) unless File.directory? File.join('seen_certs', issuer_path)
      unless File.exist? File.join('seen_certs', issuer_path, cert_path)
        File.write File.join('seen_certs', issuer_path, cert_path), cert.to_pem
        @additional_cert_store.add_cert(cert) if intermediate
      end
    end
  end

  # Get the authority key identifier
  # @param cert [OpenSSL::X509::Certificate] certificate
  # @return [String] authority key identifier or "UNKNOWN" if not included
  def get_auth_key_identifier(cert)
    authority_key_identifier_exten = cert.extensions.select { |x| x.oid == 'authorityKeyIdentifier' }

    return 'UNKNOWN' if authority_key_identifier_exten.empty?

    if authority_key_identifier_exten.length > 1
      logger.warn "Found multiple authorityKeyIdentifier Extensions in X.509 Cert for #{cert.subject}"
    end
    first_exten = authority_key_identifier_exten.first

    authority_key_identifier = if first_exten.is_a? OpenSSL::X509::Extension
                                 first_exten.value
                               else
                                 'UNKNOWN'
                               end

    match = authority_key_identifier.match(/^keyid:(.*)$/)
    return match[1].gsub(/:/, '') if match

    'UNKNOWN'
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

    certname = "#{get_subj_key_identifier(cert)}.pem"
    sync do
      unless File.exist? File.join('seen_certs', certname)
        File.write(File.join('seen_certs', certname), cert.to_pem)
        @additional_cert_store.add_cert(cert)
      end
    end
  end

  # Add an intermediate certificate to the cert store
  # @param cert [OpenSSL::X509::Certificate] certificate to add
  def self.add_known_intermediate(cert)
    TLSCertStoreHelper.instance.priv_add_cert(cert, intermediate: true)
  end

  # Check if a given certificate may be a trust anchor (based on same Issuer and Subject)
  # @param cert [OpenSSL::X509::Certificate] Certificate to check
  # @return [Boolean] if the given Cert may be a trust anchor
  def self.check_trust_anchor(cert)
    raise StandardError unless cert.is_a? OpenSSL::X509::Certificate

    logger.trace "Checking #{cert.issuer} against #{cert.subject}"

    # return
    cert.issuer.eql? cert.subject
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
