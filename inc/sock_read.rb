def sock_read(path)
  BlackBoard.sock_threads << Thread.new do
    Thread.current.name = "SocketCap #{path}"
    begin
      socket_cap_start(path)
    rescue => e
      puts "Error in Capture"
      puts e.message
      puts e.backtrace.join "\n"
    end
  end
end

def socket_cap_start(path)
  logger = BlackBoard.logger
  loop do
    logger.info "Trying to open Socket #{path}"
    begin
      socket = UNIXSocket.new(path)
    rescue Errno::ECONNREFUSED
      logger.warn "Socket #{path} could not be opened. Retrying in 5 sec"
      sleep 5
      next
    end

    socket_working = false
    bytes = ""
    begin
      loop do
        newbytes = socket.recv(15000)

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

        socket_working = true
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

          BlackBoard.pktbuf.synchronize do
            logger.trace("Inserting Packet to pktbuf (from #{from} to #{to})")
            BlackBoard.pktbuf << {source: path, request: request, from: from, from_sock: from_sock, to: to, to_sock: to_sock, pkt: radius_pkt}
            BlackBoard.pktbuf_empty.signal
          end
          StatHandler.increase :packet_captured
        end
      end
    rescue Errno::EPIPE
      logger.warn "Socket #{path} was closed (Pipe Error). Trying to reopen."
      sleep 5 unless socket_working
    end
  end
end
