# Singleton Class for handling of globally needed variables
class BlackBoard
  include Singleton

  attr_accessor :logger, :pktbuf, :pktbuf_empty, :policy_logger, :sock_threads, :policy_detail_logger,:config
  def initialize
    @logger = nil
    @policy_logger
    @policy_detail_logger
    @pktbuf = nil
    @pktbuf_empty = nil
    @sock_threads
    @config
  end

  # Getter for the script wide general logging instance
  def self.logger
    BlackBoard.instance.logger
  end
  # Setter for the script wide general logging instance
  def self.logger=(l)
    BlackBoard.instance.logger=l
  end
  # Getter for the policy logging instance
  def self.policy_logger
    BlackBoard.instance.policy_logger
  end
  # Setter for the policy logging instance
  def self.policy_logger=(l)
    BlackBoard.instance.policy_logger=l
  end
  # Getter for the policy detail logging instance
  def self.policy_detail_logger
    BlackBoard.instance.policy_detail_logger
  end
  # Setter for the policy detail logging instance
  def self.policy_detail_logger=(l)
    BlackBoard.instance.policy_detail_logger=l
  end
  # Getter for the Packet Buffer
  def self.pktbuf
    BlackBoard.instance.pktbuf
  end
  # Setter for the Packet Buffer
  def self.pktbuf=(p)
    BlackBoard.instance.pktbuf=p
  end
  # Getter for the Packet Buffer Signal
  def self.pktbuf_empty
    BlackBoard.instance.pktbuf_empty
  end
  # Setter for the Packet Buffer Signal
  def self.pktbuf_empty=(p)
    BlackBoard.instance.pktbuf_empty=p
  end
  # Getter for the Socket Thread Array
  def self.sock_threads
    BlackBoard.instance.sock_threads
  end
  # Setter for the Socket Thread Array
  def self.sock_threads=(t)
    BlackBoard.instance.sock_threads=t
  end
  # Getter for the config storage
  def self.config
    BlackBoard.instance.config
  end
  # Setter for the config storage
  def self.config=(c)
    BlackBoard.instance.config=c
  end
end