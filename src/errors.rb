# frozen_string_literal: true

# Error to be thrown whenever the parsing of the TLS Server Hello fails.
class TLSServerHelloError < StandardError; end

# Error to be thrown if the ProtocolStack parser encounters an error
class ProtocolStackError < StandardError; end

# Error to be thrown if the ProtocolStack parser encounters an error which can still be resolved
#  (e.g. a missing ServerHello, which still allows for saving the client hello)
class NonterminalProtocolStackError < ProtocolStackError; end

# Error to be thrown if a Packet can not be inserted into a PacketFlow
class PacketFlowInsertionError < StandardError; end

# Error thrown when the TLS Client Hello parsing fails.
class TLSClientHelloError < StandardError
end

# TLS Parse Error
# Is thrown on any error in parsing the TLS data.
class TLSParseError < StandardError; end

# Error to be thrown when the EAP Protocol is violated
class EAPStreamError < StandardError; end

# Error to be raised if the actual length of the packet does not match the specified length.
# This could happen if the IP packet was fragmented or the Radius Packet is faulty
class PacketLengthNotValidError < StandardError; end

# Error to be raised if a Radius Packet includes multiple State Attributes.
# This is forbidden by RFC 2865 Section 5.24
class PacketMultipleState < StandardError; end

# Error to be thrown if the RADIUS Packet violates the RFC.
# E.g. multiple State Attributes or a State Attribute in an Accept/Reject.
class ProtocolViolationError < StandardError; end

# Error to be thrown if the RADIUS Packet violates the eduroam Policy
# Currently checks against v2.8 from 2012-07-26
# https://www.eduroam.org/wp-content/uploads/2016/05/GN3-12-192_eduroam-policy-service-definition_ver28_26072012.pdf
class PolicyViolationError < StandardError; end
