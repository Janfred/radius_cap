#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

require 'socket'
require 'monitor'
require 'semantic_logger'
require 'irb'

# Require local files
require_relative './src/radiuspacket.rb'
require_relative './src/eappacket.rb'
require_relative './src/tlsclienthello.rb'
require_relative './src/tlsserverhello.rb'
require_relative './localconfig.rb'
require_relative './src/write_to_elastic.rb'
require_relative './src/macvendor.rb'
require_relative './src/radiusstream.rb'
require_relative './src/eapstream.rb'
require_relative './src/stackparser.rb'
require_relative './src/tlsstream.rb'

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []

SemanticLogger.default_level = @config[:debug_level]
SemanticLogger.add_appender(file_name: 'development.log')
SemanticLogger.add_appender(io: STDOUT, formatter: :color) if @config[:debug]

logger = SemanticLogger['radius_cap']
logger.info("Requirements done. Loading radsecproxy_cap.rb functions")

pktbuf = []
pktbuf.extend(MonitorMixin)
empty_cond = pktbuf.new_cond

ElasticHelper.initialize_elasticdata @config[:debug]

Thread.start do
  loop do
    begin
      ElasticHelper.elasticdata.synchronize do
        ElasticHelper.waitcond.wait_while { ElasticHelper.elasticdata.empty? }
        toins = ElasticHelper.elasticdata.shift

        logger.trace 'To insert: ' + toins.to_s

        username = nil
        mac = nil
        if toins[:radsec] && toins[:radsec][:attributes] && toins[:radsec][:attributes][:username]
          username = toins[:radsec][:attributes][:username]
          logger.trace 'Username from RADSEC ' + username
        end
        if toins[:radsec] && toins[:radsec][:attributes] && toins[:radsec][:attributes][:mac]
          mac = toins[:radsec][:attributes][:mac]
          logger.trace 'MAC from RADSEC ' + mac
        end

        filters = @config[:elastic_filter].select { |x|
          (x[:username].nil? || username.nil? || x[:username] == username) &&
              (x[:mac].nil? || mac.nil? || x[:mac] == mac)
        }

        if filters.length == 0
          ElasticHelper.insert_into_elastic(toins, @config[:debug], @config[:noelastic], @config[:filewrite])
        else
          logger.debug 'Filtered out Elasticdata'
        end
      end
    rescue => e
      logger.error("Error in Elastic Write", exception: e)
    end
  end
end

logger.info("Start Packet parsing")
Thread.start do
  loop do
    pktbuf.synchronize do
      empty_cond.wait_while { pktbuf.empty? }

      pkt = pktbuf.shift

      rp = nil

      begin
        rp = RadiusPacket.new(pkt[:pkt].pack('C*'))
      rescue PacketLengthNotValidError => e
        puts "PacketLengthNotValidError"
        puts e.message
        puts e.backtrace.join "\n"
      rescue => e
        puts "General error in Parsing!"
        puts e.message
        puts e.backtrace.join "\n"
      end

      begin
        RadsecStreamHelper.add_packet(rp, pkt[:request], pkt[:from], pkt[:to])
      rescue => e
        puts "Error in Packetflow!"
        puts e.message
        puts e.backtrace.join "\n"
      end
    end
  end
end

socket = nil
logger.info("Start Packet capture")
begin
  socket = UNIXSocket.new('/tmp/radsecproxy.sock')
  bytes = ""
  loop do
    bytes += socket.recv(1500)

    while bytes.length > 3
      i = 0
      request = bytes[0] == "\0"
      logger.trace "Request" if request
      logger.trace "Response" unless request
      i += 1

      from_length = bytes[i, 2].unpack('n').first
      logger.trace "From Length: #{from_length}"
      i += 2

      break if bytes.length < i + from_length + 2

      from = bytes[i, from_length]
      logger.trace "From: #{from}"
      i += from_length

      to_length = bytes[i, 2].unpack('n').first
      logger.trace "To Length: #{to_length}"
      i += 2

      break if bytes.length < i + to_length

      to = bytes[i, to_length]
      logger.trace "To: #{to}"
      i += to_length

      break if bytes.length < i+4

      radius_length = bytes[i+2,2].unpack('n').first
      logger.trace "RADIUS Length: #{radius_length}"

      break if bytes.length < i+radius_length

      radius_pkt = bytes[i, radius_length]

      bytes = bytes[i+radius_length .. -1]

      pktbuf.synchronize do
        logger.trace("Inserting Packet to pktbuf (from #{from} to #{to})")
        pktbuf << {request: request, from: from, to: to, pkt: radius_pkt}
        empty_cond.signal
      end
    end
  end
rescue Interrupt
  logger.info("Capture Interrupt")
end

logger.info("Terminating Capture")
socket.close

logger.info("Waiting for empty packet buffer")
pktbufempty = false
until pktbufempty do
  pktbuf.synchronize do
    pktbufempty = pktbuf.empty?
  end
  sleep 1
end

logger.info("Packet buffer is empty.")
logger.info("Waiting for empty elastic buffer")

elasticempty = false
until elasticempty do
  ElasticHelper.elasticdata.synchronize do
    elasticempty = ElasticHelper.elasticdata.empty?
  end
  sleep 1
end

logger.info("Elastic buffer is empty.")
logger.info("Terminating.")
