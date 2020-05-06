# TLS Stream
class TLSStream

  include SemanticLogger::Loggable

  @tlspackets

  # Initialize new TLS Stream based on EAP-TLS Packets
  # @param eaptlspackets
  def initialize(eaptlspackets)
    logger.trace("Initialize TLS Stream with #{eaptlspackets.length} packets")
    @tlspackets = []
    seen_change_cipher_spec = false
    eaptlspackets.each do |eaptlspkt|
      cur_records =  TLSRecord.parse(eaptlspkt)
      i = 0
      until seen_change_cipher_spec || i >= cur_records.length do
        cur_rec = cur_records[i]
        seen_change_cipher_spec = true if cur_rec.is_a? TLSChangeCipherSpecRecord
        if cur_rec.is_a? TLSHandshakeRecord
          cur_rec.set_handshake_type
        end
        # TODO THIS IS JUST HERE TO GET A DUMP FOR DEBUGGING
        #  This is probably a rare case and I need to decide how to deal with it.
        raise TLSParseError.new "THIS IS AN ALERT!" if cur_rec.is_a? TLSAlertRecord
      end
      @tlspackets << cur_records
    end

  end
end

class TLSRecord

  include SemanticLogger::Loggable

  attr_reader :version
  attr_reader :data

  @version
  @data
  @record_type

  def initialize(version, length, data)
    @version = version
    raise TLSParseError.new "TLS Indicated Length (#{length}) did not match actual length (#{data.length})" if @length != data.length
    @data = data
  end

  def set_custom_record_type(type)
    @record_type = type
  end

  def get_custom_record_type
    @record_type
  end

  def self.parse(data)
    cur_ptr = 0
    records = []
    while cur_ptr < data.length
      type = data[cur_ptr]
      version = data[cur_ptr + 1, 2]
      length = data[cur_ptr + 3] * 256 + data[cur_ptr + 4]
      case type
      when TLSTypes::RecordType::HANDSHAKE
        logger.trace 'TLS Handshake Record'
        records << TLSHandshakeRecord.new(version, length, data[cur_ptr + 5, length])
      when TLSTypes::RecordType::ALERT
        logger.info 'Seen TLS Record Alert'
        records << TLSAlertRecord.new(version, length, data[cur_ptr + 5, length])
      when TLSTypes::RecordType::CHANGE_CIPHER_SPEC
        logger.trace 'Change Cipher Spec'
        records << TLSChangeCipherSpecRecord.new(version, length, data[cur_ptr + 5, length])
      when TLSTypes::RecordType::APPLICATION_DATA
        logger.trace 'ApplicationData'
        records << TLSApplicationDataRecord.new(version, length, data[cur_ptr + 5, length])
      else
        logger.warn "Seen Unknown Record Type #{type}"
        rec = TLSRecord.new(version, length, data[cur_ptr + 5, length])
        rec.set_custom_record_type(type)
        records << rec
      end
      cur_ptr += 5 + length
    end
    records
  end
end

class TLSHandshakeRecord < TLSRecord
  attr_reader :handshake_type
  @handshake_type
  def initialize(version, length, data)
    @handshake_type = nil
    super
  end

  # Sets the TLS Handshake type. This Method must not be called for a TLS Handshake Record
  # after the Change Cipher Spec Record, because everything after that is encrypted. This is also
  # true for the Handshake Type and the Handshake Length, so this Method will fail because the indicated
  # length will differ, because it is encrypted.
  # @raise TLSParseError if the Handshake is too short or the indicated Length does not match the actual
  #  length of the Record.
  def set_handshake_type
    raise TLSParseError.new "The Handshake is too short" if @data.length < 4
    @handshake_type = data[0]
    @handshake_length = data[1]*256*256 + data[2]*256 + data[3]
    raise TLSParseError.new "The Indicated length did not match the actual length" if @data.length - 4 != @handshake_length
  end
end

class TLSAlertRecord < TLSRecord
  attr_reader :alert_level
  attr_reader :alert_code

  def initialize(version, length, data)
    super
    raise TLSParseError.new "The Alert must be exactly 2 Bytes long"
  end
end

class TLSChangeCipherSpecRecord < TLSRecord
end

class TLSApplicationDataRecord < TLSRecord
end

class TLSParseError < StandardError
end