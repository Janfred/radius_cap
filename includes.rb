# frozen_string_literal: true

require 'rubygems'
require 'bundler/setup'

# Require needed gems
require 'monitor'
require 'irb'
require 'semantic_logger'
require 'singleton'
require 'openssl'
require 'socket'
if @nopacketfu
  module PacketFu
    class Packet
      # left blank intentionally
    end
  end
else
  require 'packetfu'
end
require 'rufus-scheduler'

# Require local files
require_relative './src/stat_handler'
require_relative './src/radiuspacket'
require_relative './src/certificate_store'
require_relative './src/eappacket'
require_relative './src/tlsclienthello'
require_relative './src/tlsserverhello'
require_relative './localconfig'
require_relative './src/write_to_elastic'
require_relative './src/macvendor'
require_relative './src/radiusstream'
require_relative './src/radsecstream'
require_relative './src/eapstream'
require_relative './src/stackparser'
require_relative './src/tlsstream'
require_relative './src/eappwdstream'
require_relative './src/blackboard'
