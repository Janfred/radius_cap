#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'semantic_logger'
require 'packetfu'

require 'irb'
require_relative '../src/radiuspacket.rb'

SemanticLogger.default_level = :fatal

def packet_from_hex_string(str)
  # remove all whitespaces
  str.gsub!(/\s/, '')
  pktarr = [str].pack('H*').unpack('C*')
  RadiusPacket.new(pktarr)
end

puts <<EOF
Welcome to this Tool

Available Functions:

packet_from_hex_string(<string>)
  Input a string with hex bytes, separated by spaces
  e.g. "01 03 00 02 12" (not a valid RADIUS Packet)

  This Function then return a RadiusPacket with the according content
EOF

binding.irb
