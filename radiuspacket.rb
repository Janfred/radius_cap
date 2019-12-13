
class RadiusPacket
  module Type
    REQUEST = 1
    ACCEPT = 2
    REJECT = 3
    CHALLENGE = 11
  end

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
  attr_reader :length
  attr_reader :authenticator
  attr_reader :attributes

  def initialize(pkt)
    if pkt.udp_len < 20 then
      raise 'Length of packet violates RFC2865'
    end
    @raw_data = pkt.payload.unpack('C*')
    @packettype = @raw_data[0]
    @identifier = @raw_data[1]
    @length = @raw_data[2]*256 + @rawdata[3]
    @authenticator = @raw_data[4..19]
    @attributes = []
    cur_ptr = 20
    while cur_ptr < @length do
      attribute = {}
      attribute[:type] = @raw_data[cur_ptr]
      attribute[:length] = @raw_data[cur_ptr+1]
      attribute[:data] = @raw_data[cur_ptr+2..cur_ptr+attribute[:length]-1]
      attributes << attribute
      cur_ptr += attribute[:length]
    end

  end
end
