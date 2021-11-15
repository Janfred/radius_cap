#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../includes'

@config[:debug] = true
@config[:no_stat_server] = true

SemanticLogger.default_level = :trace
SemanticLogger.add_appender(io: $stdout, formatter: :color)

BlackBoard.config = @config

# Read EAP Packets from File
eapdata = File.read(ARGV[0])

eap_lines = eapdata.lines.map { |x| [x.strip].pack('H*').unpack('C*') }

eap_stream = EAPStream.new(eap_lines)

@protocol_stack = ProtocolStack.new({ type: :eap, data: eap_stream })

# Here we call the irb. This is intentional, so rubocop needs to be told that this is as expected.
binding.irb # rubocop:disable Lint/Debugger
