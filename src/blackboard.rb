class BlackBoard
  include Singleton

  attr_accessor :logger, :pktbuf, :pktbuf_empty, :policy_logger, :sock_threads
  def initialize
    @logger = nil
    @policy_logger
    @pktbuf = nil
    @pktbuf_empty = nil
    @sock_threads
  end

  def self.logger
    BlackBoard.instance.logger
  end
  def self.logger=(l)
    BlackBoard.instance.logger=l
  end
  def self.policy_logger
    BlackBoard.instance.policy_logger
  end
  def self.policy_logger=(l)
    BlackBoard.instance.policy_logger=l
  end
  def self.pktbuf
    BlackBoard.instance.pktbuf
  end
  def self.pktbuf=(p)
    BlackBoard.instance.pktbuf=p
  end
  def self.pktbuf_empty
    BlackBoard.instance.pktbuf_empty
  end
  def self.pktbuf_empty=(p)
    BlackBoard.instance.pktbuf_empty=p
  end
  def self.sock_threads
    BlackBoard.instance.sock_threads
  end
  def self.sock_threads=(t)
    BlackBoard.instance.sock_threads=t
  end
end