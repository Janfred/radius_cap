class TLSCipherSuite
  def initialize(ciphersuite)
    @external_cs = ciphersuite
    @internal_cs = @external_cs.map { |c| c.class == Array ? TLSCipherSuite.by_arr(c) : TLSCipherSuite.by_hexstr(c) }
    @internal_cs.delete nil
  end

  def humanreadable
    @internal_cs.map {|x| x[:name]}
  end

  def cipherset
    @internal_cs.map {|x| "0x%02X%02X" % x[:code]}.join " "
  end

  def pfs_avail?
    @internal_cs.select {|x| x[:pfs] }.length > 0
  end
  def only_pfs?
    @internal_cs.select {|x| !x[:pfs] && !x[:scsv]}.empty?
  end
  def anull_present?
    !@internal_cs.select {|x| x[:auth].nil? && !x[:scsv]}.empty?
  end
  def enull_present?
    !@internal_cs.select {|x| x[:encryption].nil? && !x[:scsv]}.empty?
  end
  def rc4_present?
    !@internal_cs.select {|x| !x[:encryption].nil? && x[:encryption].match(/^RC4/)}.empty?
  end
  def tripledes_present?
    !@internal_cs.select {|x| x[:encryption] == "3DES"}.empty?
  end
  def des_present?
    !@internal_cs.select {|x| !x[:encryption].nil? && x[:encryption].match(/^DES/)}.empty?
  end

  def self.by_hexstr (val)
    ar = [val[2, 4]].pack("H*").unpack("C*")
    by_arr(ar)
  end

  def self.by_arr (val)
    p = @@ciphersuites.select { |x| x[0] == val}
    $stderr.puts "Unknown Ciphersuite #{val}" if p.empty?
    return if p.empty?
    return if p.length != 1
    cipher_to_h(p.first)
  end

  def self.cipher_to_h(val)
    {code: val[0], keyxchange: val[1], auth: val[2], encryption: val[3], mode: val[4], mac: val[5], pfs: val[6], scsv: val[7], name: val[8]}
  end

  @@ciphersuites = [
#     Ciphersuite   KeyX     Auth       Encry          Mode   MAC         PFS    SCSV   Humanreadable Name
    [ [0x00, 0x00], nil,     nil,       nil,           nil,   nil,        false, false, "TLS_NULL_WITH_NULL_NULL"],
    [ [0x00, 0x01], "RSA",   "RSA",     nil,           nil,   "MD5",      false, false, "TLS_RSA_WITH_NULL_MD5"],
    [ [0x00, 0x02], "RSA",   "RSA",     nil,           nil,   "SHA",      false, false, "TLS_RSA_WITH_NULL_SHA"],
    [ [0x00, 0x03], "RSA",   "RSA",     "RC4-40",      nil,   "MD5",      false, false, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"],
    [ [0x00, 0x04], "RSA",   "RSA",     "RC4-128",     nil,   "MD5",      false, false, "TLS_RSA_WITH_RC4_128_MD5"],
    [ [0x00, 0x05], "RSA",   "RSA",     "RC4-128",     nil,   "SHA",      false, false, "TLS_RSA_WITH_RC4_128_SHA"],
    [ [0x00, 0x06], "RSA",   "RSA",     "RC2-40",      "CBC", "MD5",      false, false, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"],
    [ [0x00, 0x07], "RSA",   "RSA",     "IDEA",        "CBC", "SHA",      false, false, "TLS_RSA_WITH_IDEA_CBC_SHA"],
    [ [0x00, 0x08], "RSA",   "RSA",     "DES-40",      "CBC", "SHA",      false, false, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"],
    [ [0x00, 0x09], "RSA",   "RSA",     "DES",         "CBC", "SHA",      false, false, "TLS_RSA_WITH_DES_CBC_SHA"],
    [ [0x00, 0x0A], "RSA",   "RSA",     "3DES",        "CBC", "SHA",      false, false, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x0D], "DH",    "DSS",     "3DES",        "CBC", "SHA",      false, false, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x10], "DH",    "RSA",     "3DES",        "CBC", "SHA",      false, false, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x11], "DHE",   "DSS",     "DES-40",      "CBC", "SHA",      true,  false, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"],
    [ [0x00, 0x12], "DHE",   "DSS",     "DES",         "CBC", "SHA",      true,  false, "TLS_DHE_DSS_WITH_DES_CBC_SHA"],
    [ [0x00, 0x13], "DHE",   "DSS",     "3DES",        "CBC", "SHA",      true,  false, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x14], "DHE",   "RSA",     "DES-40",      "CBC", "SHA",      true,  false, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"],
    [ [0x00, 0x15], "DHE",   "RSA",     "DES",         "CBC", "SHA",      true,  false, "TLS_DHE_RSA_WITH_DES_CBC_SHA"],
    [ [0x00, 0x16], "DHE",   "RSA",     "3DES",        "CBC", "SHA",      true,  false, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x17], "DH",    nil,       "RC4-40",      nil,   "MD5",      false, false, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"],
    [ [0x00, 0x18], "DH",    nil,       "RC4-128",     nil,   "MD5",      false, false, "TLS_DH_anon_WITH_RC4_128_MD5"],
    [ [0x00, 0x19], "DH",    nil,       "DES-40",      "CBC", "SHA",      false, false, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"],
    [ [0x00, 0x1A], "DH",    nil,       "DES",         "CBC", "SHA",      false, false, "TLS_DH_anon_WITH_DES_CBC_SHA"],
    [ [0x00, 0x1B], "DH",    nil,       "3DES",        "CBC", "SHA",      false, false, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"],
    [ [0x00, 0x2F], "RSA",   "RSA",     "AES128",      "CBC", "SHA",      false, false, "TLS_RSA_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x30], "DH",    "DSS",     "AES128",      "CBC", "SHA",      false, false, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x31], "DH",    "RSA",     "AES128",      "CBC", "SHA",      false, false, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x32], "DHE",   "DSS",     "AES128",      "CBC", "SHA",      true,  false, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x33], "DHE",   "RSA",     "AES128",      "CBC", "SHA",      true,  false, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x34], "DH",    nil,       "AES128",      "CBC", "SHA",      false, false, "TLS_DH_anon_WITH_AES_128_CBC_SHA"],
    [ [0x00, 0x35], "RSA",   "RSA",     "AES256",      "CBC", "SHA",      false, false, "TLS_RSA_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x36], "DH",    "DSS",     "AES256",      "CBC", "SHA",      false, false, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x37], "DH",    "RSA",     "AES256",      "CBC", "SHA",      false, false, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x38], "DHE",   "DSS",     "AES256",      "CBC", "SHA",      true,  false, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x39], "DHE",   "RSA",     "AES256",      "CBC", "SHA",      true,  false, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x3A], "DH",    nil,       "AES256",      "CBC", "SHA",      false, false, "TLS_DH_anon_WITH_AES_256_CBC_SHA"],
    [ [0x00, 0x3B], "RSA",   "RSA",     nil,           nil,   "SHA256",   false, false, "TLS_RSA_WITH_NULL_SHA256"],
    [ [0x00, 0x3C], "RSA",   "RSA",     "AES128",      "CBC", "SHA256",   false, false, "TLS_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x3D], "RSA",   "RSA",     "AES256",      "CBC", "SHA256",   false, false, "TLS_RSA_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x3E], "DH",    "DSS",     "AES128",      "CBC", "SHA256",   false, false, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x3F], "DH",    "RSA",     "AES128",      "CBC", "SHA256",   false, false, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x40], "DHE",   "DSS",     "AES128",      "CBC", "SHA256",   true,  false, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x41], "RSA",   "RSA",     "CAMELLIA128", "CBC", "SHA",      false, false, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x42], "DH",    "DSS",     "CAMELLIA128", "CBC", "SHA",      false, false, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x43], "DH",    "RSA",     "CAMELLIA128", "CBC", "SHA",      false, false, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x44], "DHE",   "DSS",     "CAMELLIA128", "CBC", "SHA",      true,  false, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x45], "DHE",   "RSA",     "CAMELLIA128", "CBC", "SHA",      true,  false, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"],
    [ [0x00, 0x67], "DHE",   "RSA",     "AES128",      "CBC", "SHA256",   true,  false, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0x00, 0x68], "DH",    "DSS",     "AES256",      "CBC", "SHA256",   false, false, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x69], "DH",    "RSA",     "AES256",      "CBC", "SHA256",   false, false, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x6A], "DHE",   "DSS",     "AES256",      "CBC", "SHA256",   true,  false, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x6B], "DHE",   "RSA",     "AES256",      "CBC", "SHA256",   true,  false, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"],
    [ [0x00, 0x84], "RSA",   "RSA",     "CAMELLIA256", "CBC", "SHA256",   false, false, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x85], "DH",    "DSS",     "CAMELLIA256", "CBC", "SHA256",   false, false, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x86], "DH",    "RSA",     "CAMELLIA256", "CBC", "SHA256",   false, false, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x87], "DHE",   "DSS",     "CAMELLIA256", "CBC", "SHA256",   true,  false, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x88], "DHE",   "RSA",     "CAMELLIA256", "CBC", "SHA256",   true,  false, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"],
    [ [0x00, 0x96], "RSA",   "RSA",     "SEED",        "CBC", "SHA",      false, false, "TLS_RSA_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x97], "DH",    "DSS",     "SEED",        "CBC", "SHA",      false, false, "TLS_DH_DSS_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x98], "DH",    "RSA",     "SEED",        "CBC", "SHA",      false, false, "TLS_DH_RSA_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x99], "DHE",   "DSS",     "SEED",        "CBC", "SHA",      true,  false, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x9A], "DHE",   "RSA",     "SEED",        "CBC", "SHA",      true,  false, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x9B], "DH",    nil,       "SEED",        "CBC", "SHA",      false, false, "TLS_DH_anon_WITH_SEED_CBC_SHA"],
    [ [0x00, 0x9C], "RSA",   "RSA",     "AES128",      "GCM", "SHA256",   false, false, "TLS_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0x9D], "RSA",   "RSA",     "AES256",      "GCM", "SHA384",   false, false, "TLS_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0x9E], "DHE",   "RSA",     "AES128",      "GCM", "SHA256",   true,  false, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0x9F], "DHE",   "RSA",     "AES256",      "GCM", "SHA384",   true,  false, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0xA0], "DH",    "RSA",     "AES128",      "GCM", "SHA256",   false, false, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0xA1], "DH",    "RSA",     "AES256",      "GCM", "SHA384",   false, false, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0xA2], "DHE",   "DSS",     "AES128",      "GCM", "SHA256",   true,  false, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0xA3], "DHE",   "DSS",     "AES256",      "GCM", "SHA384",   true,  false, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0xA4], "DH",    "DSS",     "AES128",      "GCM", "SHA256",   false, false, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"],
    [ [0x00, 0xA5], "DH",    "DSS",     "AES256",      "GCM", "SHA384",   false, false, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"],
    [ [0x00, 0xBA], "RSA",   "RSA",     "CAMELLIA128", "CBC", "SHA256",   false, false, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
    [ [0x00, 0xBE], "DHE",   "RSA",     "CAMELLIA128", "CBC", "SHA256",   true,  false, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
    [ [0x00, 0xC0], "RSA",   "RSA",     "CAMELLIA256", "CBC", "SHA256",   false, false, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"],
    [ [0x00, 0xC4], "DHE",   "RSA",     "CAMELLIA256", "CBC", "SHA256",   true,  false, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"],
    [ [0x00, 0xFF], nil,     nil,       nil,           nil,   nil,        nil,   true,  "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"],
    [ [0x13, 0x01], nil,     nil,       "AES128",      "GCM", "SHA256",   false, false, "TLS_AES_128_GCM_SHA256"],
    [ [0x13, 0x02], nil,     nil,       "AES256",      "GCM", "SHA384",   false, false, "TLS_AES_256_GCM_SHA384"],
    [ [0x13, 0x03], nil,     nil,       "CHACHA20",    nil,   "POLY1305", false, false, "TLS_CHACHA20_POLY1305_SHA256"],
    [ [0xC0, 0x01], "ECDH",  "ECDSA",   nil,           nil,   "SHA",      false, false, "TLS_ECDH_ECDSA_WITH_NULL_SHA"],
    [ [0xC0, 0x02], "ECDH",  "ECDSA",   "RC4-128",     nil,   "SHA",      false, false, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"],
    [ [0xC0, 0x03], "ECDH",  "ECDSA",   "3DES",        "CBC", "SHA",      false, false, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x04], "ECDH",  "ECDSA",   "AES128",      "CBC", "SHA",      false, false, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x05], "ECDH",  "ECDSA",   "AES256",      "CBC", "SHA",      false, false, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x06], "ECDHE", "ECDSA",   nil,           nil,   "SHA",      true,  false, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"],
    [ [0xC0, 0x07], "ECDHE", "ECDSA",   "RC4-128",     nil,   "SHA",      true,  false, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"],
    [ [0xC0, 0x08], "ECDHE", "ECDSA",   "3DES",        "CBC", "SHA",      true,  false, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x09], "ECDHE", "ECDSA",   "AES128",      "CBC", "SHA",      true,  false, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x0A], "ECDHE", "ECDSA",   "AES256",      "CBC", "SHA",      true,  false, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x0B], "ECDH",  "RSA",     nil,           nil,   "SHA",      false, false, "TLS_ECDH_RSA_WITH_NULL_SHA"],
    [ [0xC0, 0x0C], "ECDH",  "RSA",     "RC4-128",     nil,   "SHA",      false, false, "TLS_ECDH_RSA_WITH_RC4_128_SHA"],
    [ [0xC0, 0x0D], "ECDH",  "RSA",     "3DES",        "CBC", "SHA",      false, false, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x0E], "ECDH",  "RSA",     "AES128",      "CBC", "SHA",      false, false, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x0F], "ECDH",  "RSA",     "AES256",      "CBC", "SHA",      false, false, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x10], "ECDHE", "RSA",     nil,           nil,   "SHA",      true,  false, "TLS_ECDHE_RSA_WITH_NULL_SHA"],
    [ [0xC0, 0x11], "ECDHE", "RSA",     "RC4-128",     nil,   "SHA",      true,  false, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"],
    [ [0xC0, 0x12], "ECDHE", "RSA",     "3DES",        "CBC", "SHA",      true,  false, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x13], "ECDHE", "RSA",     "AES128",      "CBC", "SHA",      true,  false, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x14], "ECDHE", "RSA",     "AES256",      "CBC", "SHA",      true,  false, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x1B], "SRP",   "SHA RSA", "3DES",        "CBC", "SHA",      true,  false, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x1C], "SRP",   "SHA DSS", "3DES",        "CBC", "SHA",      true,  false, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"],
    [ [0xC0, 0x1D], "SRP",   "SHA",     "AES128",      "CBC", "SHA",      true,  false, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x1E], "SRP",   "SHA RSA", "AES128",      "CBC", "SHA",      true,  false, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x1F], "SRP",   "SHA DSS", "AES128",      "CBC", "SHA",      true,  false, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"],
    [ [0xC0, 0x21], "SRP",   "SHA RSA", "AES256",      "CBC", "SHA",      true,  false, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x22], "SRP",   "SHA DSS", "AES256",      "CBC", "SHA",      true,  false, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"],
    [ [0xC0, 0x23], "ECDHE", "ECDSA",   "AES128",      "CBC", "SHA256",   true,  false, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"],
    [ [0xC0, 0x24], "ECDHE", "ECDSA",   "AES256",      "CBC", "SHA384",   true,  false, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"],
    [ [0xC0, 0x25], "ECDH",  "ECDSA",   "AES128",      "CBC", "SHA256",   false, false, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"],
    [ [0xC0, 0x26], "ECDH",  "ECDSA",   "AES256",      "CBC", "SHA384",   false, false, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"],
    [ [0xC0, 0x27], "ECDHE", "RSA",     "AES128",      "CBC", "SHA256",   true,  false, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0xC0, 0x28], "ECDHE", "RSA",     "AES256",      "CBC", "SHA384",   true,  false, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"],
    [ [0xC0, 0x29], "ECDH",  "RSA",     "AES128",      "CBC", "SHA256",   false, false, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"],
    [ [0xC0, 0x2A], "ECDH",  "RSA",     "AES256",      "CBC", "SHA384",   false, false, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"],
    [ [0xC0, 0x2B], "ECDHE", "ECDSA",   "AES128",      "GCM", "SHA256",   true,  false, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"],
    [ [0xC0, 0x2C], "ECDHE", "ECDSA",   "AES256",      "GCM", "SHA384",   true,  false, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"],
    [ [0xC0, 0x2D], "ECDH",  "ECDSA",   "AES128",      "GCM", "SHA256",   false, false, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"],
    [ [0xC0, 0x2E], "ECDH",  "ECDSA",   "AES256",      "GCM", "SHA384",   false, false, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"],
    [ [0xC0, 0x2F], "ECDHE", "RSA",     "AES128",      "GCM", "SHA256",   true,  false, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0xC0, 0x30], "ECDHE", "RSA",     "AES256",      "GCM", "SHA384",   true,  false, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0xC0, 0x31], "ECDH",  "RSA",     "AES128",      "GCM", "SHA256",   false, false, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"],
    [ [0xC0, 0x32], "ECDH",  "RSA",     "AES256",      "GCM", "SHA384",   false, false, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"],
    [ [0xC0, 0x72], "ECDHE", "ECDSA",   "CAMELLIA128", "CBC", "SHA256",   true,  false, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"],
    [ [0xC0, 0x73], "ECDHE", "ECDSA",   "CAMELLIA256", "CBC", "SHA384",   true,  false, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"],
    [ [0xC0, 0x76], "ECDHE", "RSA",     "CAMELLIA128", "CBC", "SHA256",   true,  false, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"],
    [ [0xC0, 0x77], "ECDHE", "RSA",     "CAMELLIA256", "CBC", "SHA384",   true,  false, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"],
    [ [0xC0, 0x9C], "RSA",   "RSA",     "AES128",      "CTR", "CCM",      false, false, "TLS_RSA_WITH_AES_128_CCM"],
    [ [0xC0, 0x9D], "RSA",   "RSA",     "AES256",      "CTR", "CCM",      false, false, "TLS_RSA_WITH_AES_128_CCM"],
    [ [0xC0, 0x9E], "DHE",   "RSA",     "AES128",      "CTR", "CCM",      true,  false, "TLS_DHE_RSA_WITH_AES_128_CCM"],
    [ [0xC0, 0x9F], "DHE",   "RSA",     "AES256",      "CTR", "CCM",      true,  false, "TLS_DHE_RSA_WITH_AES_256_CCM"],
    [ [0xC0, 0xA0], "RSA"  , "RSA",     "AES128",      "CTR", "CCM8",     false, false, "TLS_RSA_WITH_AES_128_CCM_8"],
    [ [0xC0, 0xA1], "RSA"  , "RSA",     "AES256",      "CTR", "CCM8",     false, false, "TLS_RSA_WITH_AES_256_CCM_8"],
    [ [0xC0, 0xA2], "DHE"  , "RSA",     "AES128",      "CTR", "CCM8",     true,  false, "TLS_DHE_RSA_WITH_AES_128_CCM_8"],
    [ [0xC0, 0xA3], "DHE"  , "RSA",     "AES256",      "CTR", "CCM8",     true,  false, "TLS_DHE_RSA_WITH_AES_256_CCM_8"],
    [ [0xC0, 0xAC], "ECDHE", "ECDSA",   "AES128",      "CTR", "CCM",      true,  false, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"],
    [ [0xC0, 0xAD], "ECDHE", "ECDSA",   "AES256",      "CTR", "CCM",      true,  false, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"],
    [ [0xC0, 0xAE], "ECDHE", "ECDSA",   "AES128",      "CTR", "CCM8",     true,  false, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"],
    [ [0xC0, 0xAF], "ECDHE", "ECDSA",   "AES256",      "CTR", "CCM8",     true,  false, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"],
    [ [0xCC, 0xA8], "ECDHE", "RSA",     "CHACHA20",    nil,   "POLY1305", true,  false, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],
    [ [0xCC, 0xA9], "ECDHE", "ECDSA",   "CHACHA20",    nil,   "POLY1305", true,  false, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"],
    [ [0xCC, 0xAA], "DHE",   "RSA",     "CHACHA20",    nil,   "POLY1305", true,  false, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"],

  ]
end

class TLSSignatureScheme
  @@signatureschemes = [
    # SigScheme     Name
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
    return if p.empty?
    return if p.length != 1
    cipher_to_h(p.first)
  end

  def self.cipher_to_h(val)
    {code: val[0], name: val[1]}
  end
end
