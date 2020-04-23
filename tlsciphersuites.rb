# This Class handles the CipherSuites
class TLSCipherSuite
  def initialize(ciphersuite)
    @external_cs = ciphersuite
    @internal_cs = @external_cs.map { |c| c.class == Array ? TLSCipherSuite.by_arr(c) : TLSCipherSuite.by_hexstr(c) }
    @internal_cs.delete nil
  end

  # Converts the Cipher Suite to an array of human readable names
  # @return [Array] Human readable Names of the CipherSuites
  def humanreadable
    @internal_cs.map {|x| x[:name]}
  end

  # Converts the Cipher Suite to a concatenated string for fingerprinting
  # @return [String] String containing all offered CipherSuites as Hex separated by space
  def cipherset
    @internal_cs.map {|x| "0x%02X%02X" % x[:code]}.join " "
  end

  # Is a PFS Cipher Suite available in the CipherSuites?
  # @return [Boolean]
  def pfs_avail?
    @internal_cs.select {|x| x[:pfs] }.length > 0
  end
  # Are all offered CipherSuites PFS?
  # This ignores TLSv1.3 Cipher Suites and SCSV
  # @return [Boolean]
  def only_pfs?
    @internal_cs.select {|x| !x[:pfs] && !x[:scsv] && !x[:tlsv13]}.empty?
  end
  # Is an aNULL (no authentication) Cipher Suite available?
  # This ignores TLSv1.3 Cipher Suites and SCSV
  # @return [Boolean]
  def anull_present?
    !@internal_cs.select {|x| x[:auth].nil? && !x[:scsv] && !x[:tlsv13]}.empty?
  end
  # Is an eNULL (no encryption) Cipher Suite available?
  # This ignores TLSv1.3 Cipher Suites and SCSV
  # @return [Boolean]
  def enull_present?
    !@internal_cs.select {|x| x[:encryption].nil? && !x[:scsv] && !x[:tlsv13]}.empty?
  end
  # Is an RC4 Cipher Suite available?
  # @return [Boolean]
  def rc4_present?
    !@internal_cs.select {|x| !x[:encryption].nil? && x[:encryption].match(/^RC4/)}.empty?
  end
  # Is a 3DES Cipher Suite available?
  # @return [Boolean]
  def tripledes_present?
    !@internal_cs.select {|x| x[:encryption] == "3DES"}.empty?
  end
  # Is a DES Cipher Suite available?
  # @return [Boolean]
  def des_present?
    !@internal_cs.select {|x| !x[:encryption].nil? && x[:encryption].match(/^DES/)}.empty?
  end

  # Get a Cipher Suite by a hex string
  # @param val [String] Hex-String of the CipherSuite in format "0xXXXX"
  # @return [Hash] CipherSuite Hash value
  def self.by_hexstr (val)
    ar = [val[2, 4]].pack("H*").unpack("C*")
    by_arr(ar)
  end

  # Get a Cipher Suite by a array of two bytes
  # @param val [Array] CipherSuite Value as Array of two bytes (e.g. [0xFF,0x00])
  # @return [Hash] CipherSuite Hash value
  def self.by_arr (val)
    p = @@ciphersuites.select { |x| x[0] == val}
    $stderr.puts "Unknown Ciphersuite #{val}" if p.empty?
    return {code: val, keyxchange: "UNKNOWN", auth: "UNKNOWN", encryption: "UNKNOWN", mode: "UNKNOWN", mac: "UNKNOWN", pfs: false, scsv: false, tlsv13: false, name: "UNKNOWN_0x#{val.pack("C*").unpack("H*")}"} if p.empty? || p.length != 1
    cipher_to_h(p.first)
  end

  # Converts a given entry from the CipherSuite array to a hash
  # @param val [Array] Row from @@ciphersuites array
  # @return [Hash] corresponding CipherSuite Hash value
  def self.cipher_to_h(val)
    {code: val[0], keyxchange: val[1], auth: val[2], encryption: val[3], mode: val[4], mac: val[5], pfs: val[6], scsv: val[7], tlsv13: val[8], name: val[9]}
  end

  # List of all supported Cipher Suites
  @@ciphersuites = [
#     Ciphersuite   KeyX     Auth       Encry          Mode   MAC         PFS    SCSV   TLS1.3 Humanreadable Name
    [ [0x00, 0x00], nil,     nil,       nil,           nil,   nil,        false, false, false, "TLS_NULL_WITH_NULL_NULL"],
    [ [0x00, 0x01], "RSA",   "RSA",     nil,           nil,   "MD5",      false, false, false, "TLS_RSA_WITH_NULL_MD5"],
    [ [0x00, 0x02], "RSA",   "RSA",     nil,           nil,   "SHA",      false, false, false, "TLS_RSA_WITH_NULL_SHA"],
    [ [0x00, 0x03], "RSA",   "RSA",     "RC4-40",      nil,   "MD5",      false, false, false, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"],
    [ [0x00, 0x04], "RSA",   "RSA",     "RC4-128",     nil,   "MD5",      false, false, false, "TLS_RSA_WITH_RC4_128_MD5"],
    [ [0x00, 0x05], "RSA",   "RSA",     "RC4-128",     nil,   "SHA",      false, false, false, "TLS_RSA_WITH_RC4_128_SHA"],
    [ [0x00, 0x06], "RSA",   "RSA",     "RC2-40",      "CBC", "MD5",      false, false, false, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"],
    [ [0x00, 0x07], "RSA",   "RSA",     "IDEA",        "CBC", "SHA",      false, false, false, "TLS_RSA_WITH_IDEA_CBC_SHA"],
    [ [0x00, 0x08], "RSA",   "RSA",     "DES-40",      "CBC", "SHA",      false, false, false, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"],
    [ [0x00, 0x09], "RSA",   "RSA",     "DES",         "CBC", "SHA",      false, false, false, "TLS_RSA_WITH_DES_CBC_SHA"],
    [ [0x00, 0x0A], "RSA",   "RSA",     "3DES",        "CBC", "SHA",      false, false, false, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x0C], "DH",    "DSS",     "DES",         "CBC", "SHA",      false, false, false, "TLS_DH_DSS_WITH_DES_CBC_SHA"],
    [ [0x00, 0x0D], "DH",    "DSS",     "3DES",        "CBC", "SHA",      false, false, false, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x0F], "DH",    "RSA",     "DES",         "CBC", "SHA",      false, false, false, "TLS_DH_RSA_WITH_DES_CBC_SHA"],
    [ [0x00, 0x10], "DH",    "RSA",     "3DES",        "CBC", "SHA",      false, false, false, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x11], "DHE",   "DSS",     "DES-40",      "CBC", "SHA",      true,  false, false, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"],
    [ [0x00, 0x12], "DHE",   "DSS",     "DES",         "CBC", "SHA",      true,  false, false, "TLS_DHE_DSS_WITH_DES_CBC_SHA"],
    [ [0x00, 0x13], "DHE",   "DSS",     "3DES",        "CBC", "SHA",      true,  false, false, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x14], "DHE",   "RSA",     "DES-40",      "CBC", "SHA",      true,  false, false, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"],
    [ [0x00, 0x15], "DHE",   "RSA",     "DES",         "CBC", "SHA",      true,  false, false, "TLS_DHE_RSA_WITH_DES_CBC_SHA"],
    [ [0x00, 0x16], "DHE",   "RSA",     "3DES",        "CBC", "SHA",      true,  false, false, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x17], "DH",    nil,       "RC4-40",      nil,   "MD5",      false, false, false, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"],
    [ [0x00, 0x18], "DH",    nil,       "RC4-128",     nil,   "MD5",      false, false, false, "TLS_DH_anon_WITH_RC4_128_MD5"],
    [ [0x00, 0x19], "DH",    nil,       "DES-40",      "CBC", "SHA",      false, false, false, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"],
    [ [0x00, 0x1A], "DH",    nil,       "DES",         "CBC", "SHA",      false, false, false, "TLS_DH_anon_WITH_DES_CBC_SHA"],
    [ [0x00, 0x1B], "DH",    nil,       "3DES",        "CBC", "SHA",      false, false, false, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x2F], "RSA",   "RSA",     "AES128",      "CBC", "SHA",      false, false, false, "TLS_RSA_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x30], "DH",    "DSS",     "AES128",      "CBC", "SHA",      false, false, false, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x31], "DH",    "RSA",     "AES128",      "CBC", "SHA",      false, false, false, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x32], "DHE",   "DSS",     "AES128",      "CBC", "SHA",      true,  false, false, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x33], "DHE",   "RSA",     "AES128",      "CBC", "SHA",      true,  false, false, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x34], "DH",    nil,       "AES128",      "CBC", "SHA",      false, false, false, "TLS_DH_anon_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x35], "RSA",   "RSA",     "AES256",      "CBC", "SHA",      false, false, false, "TLS_RSA_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x36], "DH",    "DSS",     "AES256",      "CBC", "SHA",      false, false, false, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x37], "DH",    "RSA",     "AES256",      "CBC", "SHA",      false, false, false, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x38], "DHE",   "DSS",     "AES256",      "CBC", "SHA",      true,  false, false, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x39], "DHE",   "RSA",     "AES256",      "CBC", "SHA",      true,  false, false, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x3A], "DH",    nil,       "AES256",      "CBC", "SHA",      false, false, false, "TLS_DH_anon_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x3B], "RSA",   "RSA",     nil,           nil,   "SHA256",   false, false, false, "TLS_RSA_WITH_NULL_SHA256"],
    [ [0x00, 0x3C], "RSA",   "RSA",     "AES128",      "CBC", "SHA256",   false, false, false, "TLS_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x3D], "RSA",   "RSA",     "AES256",      "CBC", "SHA256",   false, false, false, "TLS_RSA_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x3E], "DH",    "DSS",     "AES128",      "CBC", "SHA256",   false, false, false, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x3F], "DH",    "RSA",     "AES128",      "CBC", "SHA256",   false, false, false, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x40], "DHE",   "DSS",     "AES128",      "CBC", "SHA256",   true,  false, false, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x41], "RSA",   "RSA",     "CAMELLIA128", "CBC", "SHA",      false, false, false, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x42], "DH",    "DSS",     "CAMELLIA128", "CBC", "SHA",      false, false, false, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x43], "DH",    "RSA",     "CAMELLIA128", "CBC", "SHA",      false, false, false, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x44], "DHE",   "DSS",     "CAMELLIA128", "CBC", "SHA",      true,  false, false, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x45], "DHE",   "RSA",     "CAMELLIA128", "CBC", "SHA",      true,  false, false, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x67], "DHE",   "RSA",     "AES128",      "CBC", "SHA256",   true,  false, false, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x68], "DH",    "DSS",     "AES256",      "CBC", "SHA256",   false, false, false, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x69], "DH",    "RSA",     "AES256",      "CBC", "SHA256",   false, false, false, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x6A], "DHE",   "DSS",     "AES256",      "CBC", "SHA256",   true,  false, false, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x6B], "DHE",   "RSA",     "AES256",      "CBC", "SHA256",   true,  false, false, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x81], nil,     nil,       nil,           nil,   nil,        false, false, false, "TLS_GOSTR341001_WITH_28147_CNT_IMIT"],
    [ [0x00, 0x84], "RSA",   "RSA",     "CAMELLIA256", "CBC", "SHA256",   false, false, false, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x85], "DH",    "DSS",     "CAMELLIA256", "CBC", "SHA256",   false, false, false, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x86], "DH",    "RSA",     "CAMELLIA256", "CBC", "SHA256",   false, false, false, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x87], "DHE",   "DSS",     "CAMELLIA256", "CBC", "SHA256",   true,  false, false, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x88], "DHE",   "RSA",     "CAMELLIA256", "CBC", "SHA256",   true,  false, false, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x96], "RSA",   "RSA",     "SEED",        "CBC", "SHA",      false, false, false, "TLS_RSA_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x97], "DH",    "DSS",     "SEED",        "CBC", "SHA",      false, false, false, "TLS_DH_DSS_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x98], "DH",    "RSA",     "SEED",        "CBC", "SHA",      false, false, false, "TLS_DH_RSA_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x99], "DHE",   "DSS",     "SEED",        "CBC", "SHA",      true,  false, false, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x9A], "DHE",   "RSA",     "SEED",        "CBC", "SHA",      true,  false, false, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x9B], "DH",    nil,       "SEED",        "CBC", "SHA",      false, false, false, "TLS_DH_anon_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x9C], "RSA",   "RSA",     "AES128",      "GCM", "SHA256",   false, false, false, "TLS_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0x9D], "RSA",   "RSA",     "AES256",      "GCM", "SHA384",   false, false, false, "TLS_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0x9E], "DHE",   "RSA",     "AES128",      "GCM", "SHA256",   true,  false, false, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0x9F], "DHE",   "RSA",     "AES256",      "GCM", "SHA384",   true,  false, false, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0xA0], "DH",    "RSA",     "AES128",      "GCM", "SHA256",   false, false, false, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0xA1], "DH",    "RSA",     "AES256",      "GCM", "SHA384",   false, false, false, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0xA2], "DHE",   "DSS",     "AES128",      "GCM", "SHA256",   true,  false, false, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0xA3], "DHE",   "DSS",     "AES256",      "GCM", "SHA384",   true,  false, false, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0xA4], "DH",    "DSS",     "AES128",      "GCM", "SHA256",   false, false, false, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0xA5], "DH",    "DSS",     "AES256",      "GCM", "SHA384",   false, false, false, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0xBA], "RSA",   "RSA",     "CAMELLIA128", "CBC", "SHA256",   false, false, false, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
    [ [0x00, 0xBE], "DHE",   "RSA",     "CAMELLIA128", "CBC", "SHA256",   true,  false, false, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
    [ [0x00, 0xC0], "RSA",   "RSA",     "CAMELLIA256", "CBC", "SHA256",   false, false, false, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"],
    [ [0x00, 0xC4], "DHE",   "RSA",     "CAMELLIA256", "CBC", "SHA256",   true,  false, false, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"],
    [ [0x00, 0xFF], nil,     nil,       nil,           nil,   nil,        nil,   true,  false, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"],
    [ [0x13, 0x01], nil,     nil,       "AES128",      "GCM", "SHA256",   false, false, true,  "TLS_AES_128_GCM_SHA256"],
    [ [0x13, 0x02], nil,     nil,       "AES256",      "GCM", "SHA384",   false, false, true,  "TLS_AES_256_GCM_SHA384"],
    [ [0x13, 0x03], nil,     nil,       "CHACHA20",    nil,   "POLY1305", false, false, true,  "TLS_CHACHA20_POLY1305_SHA256"],
    [ [0x13, 0x04], nil,     nil,       "AES128",      "CCM", "SHA256",   false, false, true,  "TLS_AES_128_CCM_SHA256"],
    [ [0x13, 0x05], nil,     nil,       "AES128",      "CCM8","Sha256",   false, false, true,  "TLS_AES_128_CCM_8_SHA256"],
    [ [0x56, 0x00], nil,     nil,       nil,           nil,   nil,        nil,   true,  false, "TLS_FALLBACK_SCSV"],
    [ [0xC0, 0x01], "ECDH",  "ECDSA",   nil,           nil,   "SHA",      false, false, false, "TLS_ECDH_ECDSA_WITH_NULL_SHA"],
    [ [0xC0, 0x02], "ECDH",  "ECDSA",   "RC4-128",     nil,   "SHA",      false, false, false, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"],
    [ [0xC0, 0x03], "ECDH",  "ECDSA",   "3DES",        "CBC", "SHA",      false, false, false, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x04], "ECDH",  "ECDSA",   "AES128",      "CBC", "SHA",      false, false, false, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x05], "ECDH",  "ECDSA",   "AES256",      "CBC", "SHA",      false, false, false, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x06], "ECDHE", "ECDSA",   nil,           nil,   "SHA",      true,  false, false, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"],
    [ [0xC0, 0x07], "ECDHE", "ECDSA",   "RC4-128",     nil,   "SHA",      true,  false, false, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"],
    [ [0xC0, 0x08], "ECDHE", "ECDSA",   "3DES",        "CBC", "SHA",      true,  false, false, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x09], "ECDHE", "ECDSA",   "AES128",      "CBC", "SHA",      true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x0A], "ECDHE", "ECDSA",   "AES256",      "CBC", "SHA",      true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x0B], "ECDH",  "RSA",     nil,           nil,   "SHA",      false, false, false, "TLS_ECDH_RSA_WITH_NULL_SHA"],
    [ [0xC0, 0x0C], "ECDH",  "RSA",     "RC4-128",     nil,   "SHA",      false, false, false, "TLS_ECDH_RSA_WITH_RC4_128_SHA"],
    [ [0xC0, 0x0D], "ECDH",  "RSA",     "3DES",        "CBC", "SHA",      false, false, false, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x0E], "ECDH",  "RSA",     "AES128",      "CBC", "SHA",      false, false, false, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x0F], "ECDH",  "RSA",     "AES256",      "CBC", "SHA",      false, false, false, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x10], "ECDHE", "RSA",     nil,           nil,   "SHA",      true,  false, false, "TLS_ECDHE_RSA_WITH_NULL_SHA"],
    [ [0xC0, 0x11], "ECDHE", "RSA",     "RC4-128",     nil,   "SHA",      true,  false, false, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"],
    [ [0xC0, 0x12], "ECDHE", "RSA",     "3DES",        "CBC", "SHA",      true,  false, false, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x13], "ECDHE", "RSA",     "AES128",      "CBC", "SHA",      true,  false, false, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x14], "ECDHE", "RSA",     "AES256",      "CBC", "SHA",      true,  false, false, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x1B], "SRP",   "SHA RSA", "3DES",        "CBC", "SHA",      true,  false, false, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x1C], "SRP",   "SHA DSS", "3DES",        "CBC", "SHA",      true,  false, false, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x1D], "SRP",   "SHA",     "AES128",      "CBC", "SHA",      true,  false, false, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x1E], "SRP",   "SHA RSA", "AES128",      "CBC", "SHA",      true,  false, false, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x1F], "SRP",   "SHA DSS", "AES128",      "CBC", "SHA",      true,  false, false, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x21], "SRP",   "SHA RSA", "AES256",      "CBC", "SHA",      true,  false, false, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x22], "SRP",   "SHA DSS", "AES256",      "CBC", "SHA",      true,  false, false, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x23], "ECDHE", "ECDSA",   "AES128",      "CBC", "SHA256",   true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"],
    [ [0xC0, 0x24], "ECDHE", "ECDSA",   "AES256",      "CBC", "SHA384",   true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"],
    [ [0xC0, 0x25], "ECDH",  "ECDSA",   "AES128",      "CBC", "SHA256",   false, false, false, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"],
    [ [0xC0, 0x26], "ECDH",  "ECDSA",   "AES256",      "CBC", "SHA384",   false, false, false, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"],
    [ [0xC0, 0x27], "ECDHE", "RSA",     "AES128",      "CBC", "SHA256",   true,  false, false, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0xC0, 0x28], "ECDHE", "RSA",     "AES256",      "CBC", "SHA384",   true,  false, false, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"],
    [ [0xC0, 0x29], "ECDH",  "RSA",     "AES128",      "CBC", "SHA256",   false, false, false, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0xC0, 0x2A], "ECDH",  "RSA",     "AES256",      "CBC", "SHA384",   false, false, false, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"],
    [ [0xC0, 0x2B], "ECDHE", "ECDSA",   "AES128",      "GCM", "SHA256",   true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
    [ [0xC0, 0x2C], "ECDHE", "ECDSA",   "AES256",      "GCM", "SHA384",   true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"],
    [ [0xC0, 0x2D], "ECDH",  "ECDSA",   "AES128",      "GCM", "SHA256",   false, false, false, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"],
    [ [0xC0, 0x2E], "ECDH",  "ECDSA",   "AES256",      "GCM", "SHA384",   false, false, false, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"],
    [ [0xC0, 0x2F], "ECDHE", "RSA",     "AES128",      "GCM", "SHA256",   true,  false, false, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0xC0, 0x30], "ECDHE", "RSA",     "AES256",      "GCM", "SHA384",   true,  false, false, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0xC0, 0x31], "ECDH",  "RSA",     "AES128",      "GCM", "SHA256",   false, false, false, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0xC0, 0x32], "ECDH",  "RSA",     "AES256",      "GCM", "SHA384",   false, false, false, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0xC0, 0x72], "ECDHE", "ECDSA",   "CAMELLIA128", "CBC", "SHA256",   true,  false, false, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"],
    [ [0xC0, 0x73], "ECDHE", "ECDSA",   "CAMELLIA256", "CBC", "SHA384",   true,  false, false, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"],
    [ [0xC0, 0x76], "ECDHE", "RSA",     "CAMELLIA128", "CBC", "SHA256",   true,  false, false, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
    [ [0xC0, 0x77], "ECDHE", "RSA",     "CAMELLIA256", "CBC", "SHA384",   true,  false, false, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"],
    [ [0xC0, 0x9C], "RSA",   "RSA",     "AES128",      "CTR", "CCM",      false, false, false, "TLS_RSA_WITH_AES_128_CCM"],
    [ [0xC0, 0x9D], "RSA",   "RSA",     "AES256",      "CTR", "CCM",      false, false, false, "TLS_RSA_WITH_AES_128_CCM"],
    [ [0xC0, 0x9E], "DHE",   "RSA",     "AES128",      "CTR", "CCM",      true,  false, false, "TLS_DHE_RSA_WITH_AES_128_CCM"],
    [ [0xC0, 0x9F], "DHE",   "RSA",     "AES256",      "CTR", "CCM",      true,  false, false, "TLS_DHE_RSA_WITH_AES_256_CCM"],
    [ [0xC0, 0xA0], "RSA"  , "RSA",     "AES128",      "CTR", "CCM8",     false, false, false, "TLS_RSA_WITH_AES_128_CCM_8"],
    [ [0xC0, 0xA1], "RSA"  , "RSA",     "AES256",      "CTR", "CCM8",     false, false, false, "TLS_RSA_WITH_AES_256_CCM_8"],
    [ [0xC0, 0xA2], "DHE"  , "RSA",     "AES128",      "CTR", "CCM8",     true,  false, false, "TLS_DHE_RSA_WITH_AES_128_CCM_8"],
    [ [0xC0, 0xA3], "DHE"  , "RSA",     "AES256",      "CTR", "CCM8",     true,  false, false, "TLS_DHE_RSA_WITH_AES_256_CCM_8"],
    [ [0xC0, 0xAC], "ECDHE", "ECDSA",   "AES128",      "CTR", "CCM",      true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"],
    [ [0xC0, 0xAD], "ECDHE", "ECDSA",   "AES256",      "CTR", "CCM",      true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"],
    [ [0xC0, 0xAE], "ECDHE", "ECDSA",   "AES128",      "CTR", "CCM8",     true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"],
    [ [0xC0, 0xAF], "ECDHE", "ECDSA",   "AES256",      "CTR", "CCM8",     true,  false, false, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"],
    [ [0xCC, 0xA8], "ECDHE", "RSA",     "CHACHA20",    nil,   "POLY1305", true,  false, false, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],
    [ [0xCC, 0xA9], "ECDHE", "ECDSA",   "CHACHA20",    nil,   "POLY1305", true,  false, false, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"],
    [ [0xCC, 0xAA], "DHE",   "RSA",     "CHACHA20",    nil,   "POLY1305", true,  false, false, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],
    [ [0xFF, 0x85], nil,     nil,       nil,           nil,   nil,        false, false, false, "PRIVATE_0xFF_0x85"],

  ]
end

class TLSSignatureScheme
  @@signatureschemes = [
    # SigScheme     Name
    [ [0x01, 0x01], "MD5 RSA"],
    [ [0x01, 0x02], "MD5 DSA"],
    [ [0x01, 0x03], "MD5 ECDSA"],
    [ [0x02, 0x01], "rsa_pkcs1_sha1"],
    [ [0x02, 0x02], "SHA1 DSA"],
    [ [0x02, 0x03], "ecdsa_sha1"],
    [ [0x03, 0x01], "SHA224 RSA"],
    [ [0x03, 0x02], "SHA224 DSA"],
    [ [0x03, 0x03], "SHA224 ECDSA"],
    [ [0x04, 0x01], "rsa_pkcs1_sha256"],
    [ [0x04, 0x02], "SHA256 DSA"],
    [ [0x04, 0x03], "ecdsa_secp256r1_sha256"],
    [ [0x05, 0x01], "rsa_pkcs1_sha384"],
    [ [0x05, 0x02], "SHA384 DSA"],
    [ [0x05, 0x03], "ecdsa_secp384r1_sha384"],
    [ [0x06, 0x01], "rsa_pkcs1_sha512"],
    [ [0x06, 0x02], "SHA512 DSA"],
    [ [0x06, 0x03], "ecdsa_secp521r1_sha512"],
    [ [0x08, 0x04], "rsa_pss_rsae_sha256"],
    [ [0x08, 0x05], "rsa_pss_rsae_sha384"],
    [ [0x08, 0x06], "rsa_pss_rsae_sha512"],
    [ [0x08, 0x07], "ed25519"],
    [ [0x08, 0x08], "ed448"],
    [ [0x08, 0x09], "rsa_pss_pss_sha256"],
    [ [0x08, 0x0A], "rsa_pss_pss_sha384"],
    [ [0x08, 0x0B], "rsa_pss_pss_sha512"],
  ]

  def self.by_hexstr (val)
    ar = [val[2, 4]].pack("H*").unpack("C*")
    by_arr(ar)
  end

  def self.by_arr (val)
    p = @@signatureschemes.select { |x| x[0] == val}
    return {code: val, name: "UNKNOWN_0x#{val.pack("C*").unpack("H*").first}"} if p.empty? || p.length != 1
    sigscheme_to_h(p.first)
  end

  def self.sigscheme_to_h(val)
    {code: val[0], name: val[1]}
  end
end

class TLSSupportedGroups
  @@supportedgroups = [
    # Group         name
    [ [0x00, 0x01], "sect163k1"],
    [ [0x00, 0x02], "sect163r1"],
    [ [0x00, 0x03], "sect163r2"],
    [ [0x00, 0x04], "sect193r1"],
    [ [0x00, 0x05], "sect193r2"],
    [ [0x00, 0x06], "sect233k1"],
    [ [0x00, 0x07], "sect233r1"],
    [ [0x00, 0x08], "sect239k1"],
    [ [0x00, 0x09], "sect283k1"],
    [ [0x00, 0x0a], "sect283r1"],
    [ [0x00, 0x0b], "sect409k1"],
    [ [0x00, 0x0c], "sect409r1"],
    [ [0x00, 0x0d], "sect571k1"],
    [ [0x00, 0x0e], "sect571r1"],
    [ [0x00, 0x0f], "secp160k1"],
    [ [0x00, 0x10], "secp160r1"],
    [ [0x00, 0x11], "secp160r2"],
    [ [0x00, 0x12], "secp192k1"],
    [ [0x00, 0x13], "secp192r1"],
    [ [0x00, 0x14], "secp224k1"],
    [ [0x00, 0x15], "secp224r1"],
    [ [0x00, 0x16], "secp256k1"],
    [ [0x00, 0x17], "secp256r1"],
    [ [0x00, 0x18], "secp384r1"],
    [ [0x00, 0x19], "secp521r1"],
    [ [0x00, 0x1a], "brainpoolP256r1"],
    [ [0x00, 0x1b], "brainpoolP384r1"],
    [ [0x00, 0x1c], "brainpoolP512r1"],
    [ [0x00, 0x1d], "x25519"],
    [ [0x00, 0x1e], "x448"],
    [ [0x01, 0x00], "ffdhe2048"],
    [ [0x01, 0x01], "ffdhe3072"],
    [ [0x01, 0x02], "ffdhe4096"],
    [ [0x01, 0x03], "ffdhe6144"],
    [ [0x01, 0x04], "ffdhe8192"],
  ]

  def self.by_hexstr (val)
    ar = [val[2, 4]].pack("H*").unpack("C*")
    by_arr(ar)
  end

  def self.by_arr (val)
    p = @@supportedgroups.select { |x| x[0] == val }
    return {code: val, name: "UNKNOWN_#{val.pack("C*").unpack("H*").first}"} if p.empty? || p.length != 1
    group_to_h(p.first)
  end

  def self.group_to_h(val)
    {code: val[0], name: val[1]}
  end
end

class TLSServerKeyExchange
  class ECDHE
    NAMED_CURVE = 0x03
    def initialize(data, version)
      @curve_type = data[0]
      if @curve_type == TLSServerKeyExchange::ECDHE::NAMED_CURVE
        curve = data[1, 2]
        case curve
          when [0x00, 0x17], #secp256r1
               [0x00, 0x18], #secp384r1
               [0x00, 0x19], #secp521r1
               [0x00, 0x1D], #x25519
               [0x00, 0x1E]  #x448
            @curve_name = TLSSupportedGroups.by_arr(curve)
            curve_length = data[3]
            cur_ptr = 4
            curve_pubkey = data[cur_ptr, curve_length]
            cur_ptr += curve_length
            if version == [0x03, 0x03] || version == [0x03, 0x04]
              @curve_sig_algo = TLSSignatureScheme.by_arr(data[cur_ptr, 2])
              cur_ptr += 2
            else
              @curve_sig_algo = {name: "None (<TLSv1.2)", code: nil}
            end
            sig_length = data[cur_ptr]*256 + data[cur_ptr+1]
            cur_ptr += 2
            sig = data[cur_ptr, sig_length]
          else
            @curve_name = {name: "Unsupported (#{"0x%02X%02X" % curve})"}
            @curve_sig_algo = {name: "Not captured"}
            $stderr.puts "Unsupported Curve #{data[1, 2]}"
        end
      else
        $stderr.puts "Unknown Curve type #{@curve_type}"
      end
    end
    def to_h
      if @curve_sig_algo && @curve_name
        {sig_scheme: @curve_sig_algo[:name], curve_name: @curve_name[:name]}
      else
        {}
      end
    end
  end

  class DHE
    def initialize(data, version)
    end
    def to_h
    end
  end

  def self.parse(data, cipher, version)
    if TLSCipherSuite.by_arr(cipher)[:keyxchange] == "ECDHE"
      return TLSServerKeyExchange::ECDHE.new(data, version)
    else
      return nil
    end
  end
end
