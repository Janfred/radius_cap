# TLS Stream
class TLSStream

  include SemanticLogger::Loggable

  attr_reader :tlspackets, :alerted
  @tlspackets
  @alerted

  # Initialize new TLS Stream based on EAP-TLS Packets
  # @param eaptlspackets
  def initialize(eaptlspackets)
    logger.trace("Initialize TLS Stream with #{eaptlspackets.length} packets")
    @tlspackets = []
    @alerted = false
    seen_change_cipher_spec = false
    eaptlspackets.each do |eaptlspkt|
      cur_records = TLSRecord.parse(eaptlspkt, seen_change_cipher_spec)
      i = 0
      until seen_change_cipher_spec || i >= cur_records.length do
        cur_rec = cur_records[i]
        seen_change_cipher_spec = true if cur_rec.is_a? TLSChangeCipherSpecRecord
        if cur_rec.is_a? TLSHandshakeRecord
          cur_rec.set_handshake_type
        end
        # TODO THIS IS JUST HERE TO GET A DUMP FOR DEBUGGING
        #  This is probably a rare case and I need to decide how to deal with it.
        if cur_rec.is_a? TLSAlertRecord
          logger.warn "Seen a TLS Alert #{cur_rec.ispect_alert}"
          @alerted = true
          return
        end
        i += 1
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
    raise TLSParseError.new "TLS Indicated Length (#{length}) did not match actual length (#{data.length})" if length != data.length
    @data = data
  end

  def set_custom_record_type(type)
    @record_type = type
  end

  def get_custom_record_type
    @record_type
  end

  def self.parse(data,change_cipher_spec_seen = false)
    logger.trace "Parse TLS Record set with length #{data.length}"
    cur_ptr = 0
    records = []
    while cur_ptr < data.length
      type = data[cur_ptr]
      version = data[cur_ptr + 1, 2]
      length = data[cur_ptr + 3] * 256 + data[cur_ptr + 4]
      case type
      when TLSTypes::RecordType::HANDSHAKE
        logger.trace 'TLS Handshake Record'
        if change_cipher_spec_seen
          records << TLSHandshakeRecord.new(version, length, data[cur_ptr + 5, length])
        else
          records += TLSHandshakeRecord.parse_handshakes(version, length, data[cur_ptr + 5, length])
        end
      when TLSTypes::RecordType::ALERT
        logger.info 'Seen TLS Record Alert'
        begin
          records << TLSAlertRecord.new(version, length, data[cur_ptr + 5, length])
        rescue TLSParseError => e
          if change_cipher_spec_seen
            # Once we have seen the change_cipher_spec the part of the ServerHello which can be analyzed is through
            # So now we have no further need of throwing an error.
            logger.info 'Rescued TLSParseError: ' + e.message
          else
            # If the change_cipher_spec has not yet been seen, the alert probably came before the Handshake.
            # In this case we raise the error to let the next higher instance deal with it.
            raise e
          end
        end
      when TLSTypes::RecordType::CHANGE_CIPHER_SPEC
        logger.trace 'Change Cipher Spec'
        records << TLSChangeCipherSpecRecord.new(version, length, data[cur_ptr + 5, length])
        change_cipher_spec_seen = true
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
    @handshake_length = data[1] * 256 * 256 + data[2] * 256 + data[3]
    raise TLSParseError.new "The Indicated length did not match the actual length" if @data.length - 4 != @handshake_length
  end

  def self.parse_handshakes(version, length, data)
    cur_ptr = 0
    to_return = []

    logger.trace "Parsing TLS Handshake Record with indicated length #{length} and data length #{data.length}"
    while cur_ptr < data.length
      logger.trace "First data: #{data[0,4].inspect}"
      cur_type = data[cur_ptr]
      cur_length = data[cur_ptr + 1] * 256 * 256 + data[cur_ptr + 2] * 256 + data[cur_ptr + 3]
      logger.trace "Type: #{cur_type}, Length: #{cur_length}"
      to_return << TLSHandshakeRecord.new(version, cur_length + 4, data[cur_ptr, cur_length + 4])
      cur_ptr += cur_length + 4
      logger.trace "New pointer position: #{cur_ptr}"
    end

    raise TLSParseError.new "The indicated lengths did not match with the data" unless cur_ptr == data.length

    to_return
  end
end

class TLSAlertRecord < TLSRecord
  attr_reader :alert_level
  attr_reader :alert_code

  def initialize(version, length, data)
    super
    raise TLSParseError.new "The Alert must be exactly 2 Bytes long. Actual length #{data.length}" if data.length != 2
    @alert_level = data[0]
    @alert_code = data[1]
  end

  def ispect_alert
    "Level #{@alert_level} (#{level_string}): #{code_string} (#{@alert_code})"
  end

  private
  def level_string
    case @alert_level
    when 2
      "Fatal"
    when 1
      "Warning"
    else
      "Unknown"
    end
  end

  def code_string
    TLSTypes::Alerts.get_altert_name_by_code(@alert_code)
  end
end

class TLSChangeCipherSpecRecord < TLSRecord
end

class TLSApplicationDataRecord < TLSRecord
end

class TLSParseError < StandardError
end
