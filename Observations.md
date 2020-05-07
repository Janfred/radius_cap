# Observations

In this file some (in some cases very weird) observations will be listed.
These observations will not be representative and may also be the result of some
specific phaenomena like single bit swaps.

Nonetheless, this might give some interesting insights in
implementation issues and edge cases when dealing with RADIUS, EAP and EAP-TLS

## Unanswered TLS Server Hallo and Acknowledgement loop

In this case the client and server agreed to an EAP-TLS based EAP Method and started exchanging
the TLS ClientHello and the TLS ServerHello. After the last fragment of the TLS ServerHello (in this case the TLS Server Hello
was 6 EAP-Packets long) and the last Fragment had no Flags set, the Client answered with an EAP-TLS 
Acknowledgement Packet (No Flags set, Empty Payload)
The Server then sent a Packet with the Flag LengthIncluded set, a coded Length of 0 Byte and no payload, which the Client
then again acknowledged with an EAP-TLS Acknowledgement.
This continued for another ~42 Packets, after which the FreeRADIUS gave up and sent a Reject.
The Error message in the Freeradius:
```
rlm_eap (EAP): Aborting! More than 50 roundtrips made in session with state 0x<omitted>
```

This case might not be that rare, it occured twice within an observation period of 3 hours.

## EAP-TLS Flags set to 0x01 and second TLS CLientHello + TLS Alert protocol_error

In this case the client and server agreed on EAP-PEAP and started the communication.
After the fifth Packet of the TLS Server Hello (which was not yet finished) the Client sent a packet with the Flags set to
0x01, which appeard to contain another TLS Client Hello, followed by a fatal TLS Alert 'protocol_error'. (Detailed Analysis is still in progress.)
 
 According to RFC 5216 Section 3 the last 5 bit of the Flags MUST be set to zero and MUST be ignored by the
receiver.
In this case the remote RADIUS Server immediately rejected the client.
Unfortunately this was a proxied request, so I have no log data except for the standard `Login incorrect (Home Server says so)`

The effected user was able to login shortly after this incident, so it was just a temporary issue.

This case is in fact interesting, because it might show issues with interoperability if at some point the reserved Flags
in EAP-TLS will be used, but Implementations violate the standard and reject the client if these flags are set.
But the set flags are probably not the reason for the rejection.

## Repeated EAP Identity

In this case a remote client sent a EAP-Identity containing the username (`eduroam@uni-bremen.de`). The server
answered with an EAP-TTLS Type and a EAP-TLS Start Packet.
The Client then retransmitted the EAP-Identity.
After the retransmission and another EAP-TLS Start Packet the client then started with an EAP-TTLS communication and the TLS
Client Hello.