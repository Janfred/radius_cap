# Error to be raised if the actual length of the packet does not match the specified length.
# This could happen if the IP packet was fragmented or the Radius Packet is faulty
class PacketLengthNotValidError < StandardError
end

# Error to be raised if a Radius Packet includes multiple State Attributes.
# This is forbidden by RFC 2865 Section 5.24
class PacketMultipleState < StandardError
end

# A Radius Packet with all attributes and a reassembled EAP Message
class RadiusPacket
  include SemanticLogger::Loggable

  # All supported RADIUS Types
  module Type
    REQUEST = 1
    ACCEPT = 2
    REJECT = 3
    CHALLENGE = 11
  end

  # All supported RADIUS attributes
  module Attribute
    USERNAME             =   1
    USERPASSWORD         =   2
    NASIPADDRESS         =   4
    NASPORT              =   5
    SERVICETYPE          =   6
    FRAMEDPROTOCOL       =   7
    FRAMEDIPADDRESS      =   8
    FRAMEDIPNETMASK      =   9
    FRAMEDROUTING        =  10
    FRAMEDMTU            =  12
    FRAMEDCOMPRESSION    =  13
    LOGINIPHOST          =  14
    REPLYMESSAGE         =  18
    REMOTEACCESSSERVICE  =  22
    STATE                =  24
    VENDORSPECIFIC       =  26
    SESSIONTIMEOUT       =  27
    CALLEDSTATIONID      =  30
    CALLINGSTATIONID     =  31
    NASIDENTIFIER        =  32
    PROXYSTATE           =  33
    ACCTSESSIONID        =  44
    ACCTMULTISESSIONID   =  50
    EVENTTIMESTAMP       =  55
    NASPORTTYPE          =  61
    TUNNELTYPE           =  64
    TUNNELMEDIUMTYPE     =  65
    TUNNELCLIENTENDPOINT =  66
    CONNECTINFO          =  77
    CONFIGURATIONTOKEN   =  78
    EAPMESSAGE           =  79
    MESSAGEAUTHENTICATOR =  80
    TUNNELPRIVATEGROUPID =  81
    NASPORTID            =  87
    CUI                  =  89
    NASIPV6ADDRESS       =  95
    FRAMEDINTERFACEID    =  96
    FRAMEDIPV6PREFIX     =  97
    EAPKEYNAME           = 102
    OPERATORNAME         = 126
    LOCATIONINFORMATION  = 127
    LOCATIONDATA         = 128
    LOCATIONCAPABLE      = 131
    MOBILITYDOMAINID     = 177
    WLANPAIRWISECIPHER   = 186
    WLANGROUPCIPHER      = 187
    WLANAKMSUITE         = 188
    WLANGROUPMGMTCIPHER  = 189
    WLANRFBAND           = 190
  end

  attr_reader :raw_data
  attr_reader :packettype
  attr_reader :identifier
  attr_reader :length
  attr_reader :authenticator
  attr_reader :attributes
  attr_reader :eap
  attr_reader :udp
  attr_reader :state

  def initialize(pkt)
    if pkt.udp_len < 20
      raise 'Length of packet violates RFC2865'
    end

    # Save UDP Header information (needed for matching packets
    @udp = {src: {ip: pkt.ip_saddr, port: pkt.udp_sport}, dst: {ip: pkt.ip_daddr, port: pkt.udp_dport}}

    @raw_data = pkt.payload.unpack('C*')

    # Parse Radius Headers
    @packettype = @raw_data[0]
    @identifier = @raw_data[1]
    @length = @raw_data[2]*256 + @raw_data[3]

    # This case should actually not happen, but it happened. (I hate IP fragmentation)
    if @length != @raw_data.length
      raise PacketLengthNotValidError, "Raw data length #{@raw_data.length} does not match identified length #{@length}"
    end

    @authenticator = @raw_data[4..19]

    @attributes = []
    @state = nil

    cur_ptr = 20
    while cur_ptr < @length do
      attribute = {}
      attribute[:type] = @raw_data[cur_ptr]
      attribute[:length] = @raw_data[cur_ptr+1]
      attribute[:data] = @raw_data[cur_ptr+2..cur_ptr+attribute[:length]-1]
      attributes << attribute
      cur_ptr += attribute[:length]
      if attribute[:type] == RadiusPacket::Attribute::STATE
        # There should be only one state
        raise PacketMultipleState, 'multiple state attributes present' unless @state.nil?
        @state = attribute[:data]
      end
    end

    parse_eap
  end

  # Reassembles the EAP messages by concatenating the contents of all EAP-Message attributes.
  def parse_eap
    @attributes.each do |a|
      next unless a[:type] == RadiusPacket::Attribute::EAPMESSAGE
      @eap ||= []
      @eap += a[:data]
    end
  end

  def inspect
    str  = "#<#{self.class.name}: "
    str += case @packettype
      when RadiusPacket::Type::REQUEST
        "Request"
      when RadiusPacket::Type::ACCEPT
        "Accept"
      when RadiusPacket::Type::REJECT
        "Reject"
      when RadiusPacket::Type::CHALLENGE
        "Challenge"
      else
        "UNKNOWN!"
    end
    str += ' id:0x%02X' % @identifier
    @attributes.each do |a|
      case a[:type]
        when RadiusPacket::Attribute::USERNAME
          str += " Username: #{a[:data].pack('C*')}"
        when RadiusPacket::Attribute::USERPASSWORD
        when RadiusPacket::Attribute::NASIPADDRESS
        when RadiusPacket::Attribute::NASPORT
        when RadiusPacket::Attribute::SERVICETYPE
        when RadiusPacket::Attribute::FRAMEDPROTOCOL
        when RadiusPacket::Attribute::FRAMEDIPADDRESS
        when RadiusPacket::Attribute::FRAMEDIPNETMASK
        when RadiusPacket::Attribute::FRAMEDROUTING
        when RadiusPacket::Attribute::FRAMEDMTU
        when RadiusPacket::Attribute::FRAMEDCOMPRESSION
        when RadiusPacket::Attribute::LOGINIPHOST
        when RadiusPacket::Attribute::REPLYMESSAGE
        when RadiusPacket::Attribute::REMOTEACCESSSERVICE
        when RadiusPacket::Attribute::STATE
          str += " State: 0x#{a[:data].pack('C*').unpack('H*').first}"
        when RadiusPacket::Attribute::VENDORSPECIFIC
        when RadiusPacket::Attribute::SESSIONTIMEOUT
        when RadiusPacket::Attribute::CALLEDSTATIONID
        when RadiusPacket::Attribute::CALLINGSTATIONID
          str += " Calling-Station-Id: #{a[:data].pack('C*')}"
        when RadiusPacket::Attribute::NASIDENTIFIER
        when RadiusPacket::Attribute::PROXYSTATE
          str += " Proxy-State: 0x#{a[:data].pack('C*').unpack('H*').first}"
        when RadiusPacket::Attribute::ACCTSESSIONID
        when RadiusPacket::Attribute::ACCTMULTISESSIONID
        when RadiusPacket::Attribute::EVENTTIMESTAMP
        when RadiusPacket::Attribute::NASPORTTYPE
        when RadiusPacket::Attribute::TUNNELTYPE
        when RadiusPacket::Attribute::TUNNELMEDIUMTYPE
        when RadiusPacket::Attribute::TUNNELCLIENTENDPOINT
        when RadiusPacket::Attribute::CONNECTINFO
        when RadiusPacket::Attribute::CONFIGURATIONTOKEN
        when RadiusPacket::Attribute::EAPMESSAGE
        when RadiusPacket::Attribute::MESSAGEAUTHENTICATOR
        when RadiusPacket::Attribute::TUNNELPRIVATEGROUPID
        when RadiusPacket::Attribute::NASPORTID
        when RadiusPacket::Attribute::CUI
        when RadiusPacket::Attribute::NASIPV6ADDRESS
        when RadiusPacket::Attribute::FRAMEDINTERFACEID
        when RadiusPacket::Attribute::FRAMEDIPV6PREFIX
        when RadiusPacket::Attribute::EAPKEYNAME
        when RadiusPacket::Attribute::OPERATORNAME
        when RadiusPacket::Attribute::LOCATIONINFORMATION
        when RadiusPacket::Attribute::LOCATIONDATA
        when RadiusPacket::Attribute::LOCATIONCAPABLE
        when RadiusPacket::Attribute::MOBILITYDOMAINID
        when RadiusPacket::Attribute::WLANPAIRWISECIPHER
        when RadiusPacket::Attribute::WLANGROUPCIPHER
        when RadiusPacket::Attribute::WLANAKMSUITE
        when RadiusPacket::Attribute::WLANGROUPMGMTCIPHER
        when RadiusPacket::Attribute::WLANRFBAND
        else
          str += " Unknown Type #{a[:type]}"
      end
    end
    # Add end and return
    str + ">"
  end
end
