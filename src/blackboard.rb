# frozen_string_literal: true

# Singleton Class for handling of globally needed variables
class BlackBoard
  include Singleton

  attr_accessor :logger, :pktbuf, :pktbuf_empty, :policy_logger, :sock_threads, :policy_detail_logger, :config, :profilers

  def initialize
    @logger = nil
    @policy_logger
    @policy_detail_logger
    @pktbuf = nil
    @pktbuf_empty = nil
    @sock_threads
    @config
    @profilers = {}
  end

  # Getter for the script wide general logging instance
  def self.logger
    BlackBoard.instance.logger
  end

  # Setter for the script wide general logging instance
  def self.logger=(log)
    BlackBoard.instance.logger = log
  end

  # Getter for the policy logging instance
  def self.policy_logger
    BlackBoard.instance.policy_logger
  end

  # Setter for the policy logging instance
  def self.policy_logger=(pol_log)
    BlackBoard.instance.policy_logger = pol_log
  end

  # Getter for the policy detail logging instance
  def self.policy_detail_logger
    BlackBoard.instance.policy_detail_logger
  end

  # Setter for the policy detail logging instance
  def self.policy_detail_logger=(det_log)
    BlackBoard.instance.policy_detail_logger = det_log
  end

  # Getter for the Packet Buffer
  def self.pktbuf
    BlackBoard.instance.pktbuf
  end

  # Setter for the Packet Buffer
  def self.pktbuf=(buf)
    BlackBoard.instance.pktbuf = buf
  end

  # Getter for the Packet Buffer Signal
  def self.pktbuf_empty
    BlackBoard.instance.pktbuf_empty
  end

  # Setter for the Packet Buffer Signal
  def self.pktbuf_empty=(sig)
    BlackBoard.instance.pktbuf_empty = sig
  end

  # Getter for the Socket Thread Array
  def self.sock_threads
    BlackBoard.instance.sock_threads
  end

  # Setter for the Socket Thread Array
  def self.sock_threads=(thr)
    BlackBoard.instance.sock_threads = thr
  end

  # Getter for the config storage
  def self.config
    BlackBoard.instance.config
  end

  # Setter for the config storage
  def self.config=(conf)
    BlackBoard.instance.config = conf
  end

  # Getter for the profiler
  def self.profilers
    BlackBoard.instance.profilers
  end

  # Setter for the profiler
  def self.profilers=(p)
    BlackBoard.instance.profilers=p
  end
end

