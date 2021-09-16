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
      # left blank intentionallyg
    end
  end
else
  require 'packetfu'
end
require 'rufus-scheduler'

# Require local files
require_relative './src/stat_handler.rb'
require_relative './src/radiuspacket.rb'
require_relative './src/eappacket.rb'
require_relative './src/tlsclienthello.rb'
require_relative './src/tlsserverhello.rb'
require_relative './localconfig.rb'
require_relative './src/write_to_elastic.rb'
require_relative './src/macvendor.rb'
require_relative './src/radiusstream.rb'
require_relative './src/radsecstream.rb'
require_relative './src/eapstream.rb'
require_relative './src/stackparser.rb'
require_relative './src/tlsstream.rb'
require_relative './src/eappwdstream.rb'
require_relative './src/blackboard.rb'