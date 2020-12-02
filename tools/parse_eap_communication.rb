
require '../includes'

@config[:debug] = true

SemanticLogger.default_level = :trace
SemanticLogger.add_appender(io:STDOUT, formatter: :color)

# Read EAP Packets from File
eapdata = File.read(ARGV[0])

eap_lines = eapdata.lines.map{ |x| [x.strip].pack('H*').unpack('C*')}

eap_stream = EAPStream.new(eap_lines)

@protocol_stack = ProtocolStack.new({type: :eap, data: eap_stream})

binding.irb