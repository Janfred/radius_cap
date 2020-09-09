#!/bin/bash

# We need to remove the local sockets first
rm /tmp/radius-server-1.sock || true
rm /tmp/radius-server-2.sock || true

#      This is the local socket  :  This is the remote socket
ssh -NL /tmp/radius-server-1.sock:/tmp/radsecproxy.sock radius-server-1 &
ssh -NL /tmp/radius-server-2.sock:/tmp/radsecproxy.sock radius-server-2
