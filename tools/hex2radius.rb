#!/usr/bin/env ruby
# frozen_string_literal: true

require 'rubygems'
require 'bundler/setup'
require 'semantic_logger'
require 'packetfu'

require 'irb'
require_relative '../src/radiuspacket'

SemanticLogger.default_level = :fatal

def packet_from_hex_string(str)
  # remove all whitespaces
  str.gsub!(/\s/, '')
  pktarr = [str].pack('H*').unpack('C*')
  RadiusPacket.new(pktarr)
end

puts <<~USAGEINSTRUCTIONS
  Welcome to this Tool

  Available Functions:

  packet_from_hex_string(<string>)
    Input a string with hex bytes, separated by spaces
    e.g. "01 03 00 02 12" (not a valid RADIUS Packet)

    This Function then return a RadiusPacket with the according content
USAGEINSTRUCTIONS

# Here we call the IRB. This is intentional, so rubocop needs to be told that this is on purpose
binding.irb # rubocop:disable Lint/Debugger
