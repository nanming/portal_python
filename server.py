#!/usr/bin/python

import pyrad
from pyrad import dictionary, packet, server
import sys
from random import Random
import struct, socket
try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # BBB for python 2.4
    import md5
    md5_constructor = md5.new

class FakeServer(server.Server):
    def _HandlePacket(self, pkt):
        server.Server._HandlePacket(self, pkt)
        if isinstance(pkt, packet.Packet):
            pass
        else:
            print >>sys.stderr, 'the pack recived is not a valid portal packet'
            sys.exit(1)
	if pkt.code == 8:
	    print pkt, pkt.reqid, socket.inet_ntoa(struct.pack('I',socket.htonl(pkt.userip)))

srv=FakeServer(dict=dictionary.Dictionary("dictionary"))
srv.BindToAddress("")
srv.Run()
