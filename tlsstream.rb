# TLS Stream
class TLSStream

  include SemanticLogger::Loggable

  # Initialize new TLS Stream based on EAP-TLS Packets
  # @param eaptlspackets
  def initialize(eaptlspackets)
    logger.trace("Initialize TLS Stream with #{eaptlspackets.length} packets")
  end
end