#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'

# Require needed gems
require 'socket'
require 'irb'
require 'monitor'
require 'semantic_logger'

# Require local files
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

@config[:debug] = false if @config[:debug].nil?
@config[:eap_timeout] ||= 60
@config[:noelastic] = false if @config[:noelastic].nil?
@config[:filewrite] = false if @config[:filewrite].nil?
@config[:debug_level] ||= :warn
@config[:elastic_filter] ||= []
@config[:socket_files] ||= ['/tmp/radsecproxy.sock']

SemanticLogger.default_level = @config[:debug_level]
SemanticLogger.add_appender(file_name: 'development.log')
SemanticLogger.add_appender(io: STDOUT, formatter: :color) if @config[:debug]
SemanticLogger.add_appender(file_name: 'policy_violation.log', filter: /PolicyViolation/)

logger = SemanticLogger['radius_cap']
policylogger = SemanticLogger['PolicyViolation']
logger.info("Requirements done. Loading radsecproxy_cap.rb functions")

@localvars = {}
@localvars[:logger] = logger
@localvars[:pktbuf] = []
@localvars[:pktbuf].extend(MonitorMixin)
@localvars[:empty_cond] = @localvars[:pktbuf].new_cond


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
    @localvars[:pktbuf].synchronize do
      @localvars[:empty_cond].wait_while { @localvars[:pktbuf].empty? }

      pkt = @localvars[:pktbuf].shift

      rp = nil

      begin
        rp = RadiusPacket.new(pkt[:pkt].unpack('C*'))
        rp.check_policies
      rescue PacketLengthNotValidError => e
        puts "PacketLengthNotValidError"
        puts e.message
        puts e.backtrace.join "\n"
        next
      rescue ProtocolViolationError => e
        policylogger.info e.class.to_s + ' ' + e.message + (pkt[:request]?'Request':'Response') + ' From: ' + pkt[:from].inspect + ' To: ' + pkt[:to].inspect + ' Realm: ' + (rp.realm || "")
      rescue PolicyViolationError => e
        policylogger.info e.class.to_s + ' ' + e.message + (pkt[:request]?'Request':'Response') + ' From: ' + pkt[:from].inspect + ' To: ' + pkt[:to].inspect + ' Realm: ' + (rp.realm || "")
      rescue => e
        puts "General error in Parsing!"
        puts e.message
        puts e.backtrace.join "\n"
        next
      end

      next if rp.nil?

      begin
        RadsecStreamHelper.add_packet(rp, pkt[:request], [pkt[:from], pkt[:from_sock], pkt[:source]], [pkt[:to], pkt[:to_sock], pkt[:source]])
      rescue PacketFlowInsertionError => e
        logger.warn 'PacketFlowInsertionError: ' + e.message
      rescue => e
        puts "Error in Packetflow!"
        puts e.message
        puts e.backtrace.join "\n"
      end
    end
  end
end

def socket_cap_start(path)
  logger = @localvars[:logger]
  loop do
    logger.info "Trying to open Socket #{path}"
    begin
      socket = UNIXSocket.new(path)
    rescue Errno::ECONNREFUSED
      logger.warn "Socket #{path} could not be opened. Retrying in 5 sec"
      sleep 5
      next
    end

    bytes = ""
    begin
      loop do
        newbytes = socket.recv(1500)

        # This is a workaround.
        # The socket does not recognize if the remote end is closed.
        # If we haven't received anything, it is likely that the socket was closed.
        # So we send out an empty string. This does not effect the socket owner, but
        # it raises a Broken Pipe Error, if the socket isn't open any more.
        # If we didn't receive anything, we wait for 0.1 seconds to reduce the load.
        if newbytes == ""
          socket.send "", 0
          sleep 0.1
          next
        end
        bytes += newbytes

        while bytes.length > 11

          # Check if the packet is a Request or a response
          i = 0
          request = bytes[0] == "\0"
          logger.trace "Request" if request
          logger.trace "Response" unless request
          i += 1

          # Now we unpack the "From" length
          from_length = bytes[i, 2].unpack('n').first
          logger.trace "From Length: #{from_length}"
          i += 2

          break if bytes.length < i + from_length + 6
          # The +6 contains of 2 Byes From length and 4 Bytes From SocketID

          # And we fetch the actual "From"
          from = bytes[i, from_length]
          logger.trace "From: #{from}"
          i += from_length

          # And we fetch the from socket id
          from_sock = bytes[i, 4].unpack('N').first
          i += 4

          # Now we fetch the "To" length
          to_length = bytes[i, 2].unpack('n').first
          logger.trace "To Length: #{to_length}"
          i += 2

          break if bytes.length < i + to_length + 4
          # The +4 covers the To SocketID

          # And we fetch the actual "To"
          to = bytes[i, to_length]
          logger.trace "To: #{to}"
          i += to_length

          # And we fetch the To socket id
          to_sock = bytes[i, 4].unpack('N').first
          i += 4


          break if bytes.length < i+4

          radius_length = bytes[i+2,2].unpack('n').first
          logger.trace "RADIUS Length: #{radius_length}"

          break if bytes.length < i+radius_length

          radius_pkt = bytes[i, radius_length]

          bytes = bytes[i+radius_length .. -1]

          @localvars[:pktbuf].synchronize do
            logger.trace("Inserting Packet to pktbuf (from #{from} to #{to})")
            @localvars[:pktbuf] << {source: path, request: request, from: from, from_sock: from_sock, to: to, to_sock: to_sock, pkt: radius_pkt}
            @localvars[:empty_cond].signal
          end
        end
      end
    rescue Errno::EPIPE
      logger.warn "Socket #{path} was closed (Pipe Error). Trying to reopen."
    end
  end
end

socket_threads = []
logger.info("Start Packet capture")
begin
  @config[:socket_files].each do |path|
    socket_threads << Thread.new do
      begin
        socket_cap_start(path)
      rescue => e
        puts "Error in Capture"
        puts e.message
        puts e.backtrace.join "\n"
      end
    end
  end
  sleep

rescue Interrupt
  logger.info("Capture Interrupt")
  socket_threads.each do |thr|
    thr.exit
  end
end

logger.info("Terminating Capture")

logger.info("Waiting for empty packet buffer")
pktbufempty = false
until pktbufempty do
  @localvars[:pktbuf].synchronize do
    pktbufempty = @localvars[:pktbuf].empty?
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
