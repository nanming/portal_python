#!/usr/bin/python

import socket, sys
import pyrad.packet
import os
import struct
from pyrad.client import Client
from pyrad.dictionary import Dictionary
try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # BBB for python 2.4
    import md5
    md5_constructor = md5.new


def error_code(Packet):
    if Packet.errcode == 1:
	    #if Packet.code == pyrad.packet.AckChallenge:
		    #print 'Challenge Request is denied'
	    #else:
		    #print 'The Request is denied'
	    sys.exit(3)
    elif Packet.errcode == 2:
	    #print 'The connection has been created'
	    sys.exit(4)
    elif Packet.errcode == 3:
	    #print 'The request is authenticating'
	    sys.exit(5)
    elif Packet.errcode == 4:
	    #print 'challenge Request failed, unknow error'
	    sys.exit(6)

def check_ip(ipaddr):
    addr=ipaddr.strip().split('.') 
    if len(addr) != 4: 
            #print >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
            sys.exit(100)
    for i in range(4):
            try:
                    addr[i]=int(addr[i]) 
            except:
                      #print >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
                    sys.exit(100)
            if addr[i]<=255 and addr[i]>=0:   
                    pass
            else:
		    #print >> sys.stderr, 'The ipaddr %s is invalid' %ipaddr
                    sys.exit(100)
            i+=1

def usage():
    print(
"""Usage: aaa.py auth nasip userip portalport usermac username passwd --- login
       aaa.py kick nasip userip portalport usermac --- logout """)
    sys.exit(100)

# sys.argv[2] nasip
# sys.argv[3] userip
# sys.argv[4] portalport
# sys.argv[5] usermac
# sys.argv[6] username
# sys.argv[7] password 
#srv=Client(server="192.168.0.92", dict=Dictionary("dictionary"))
# Main function 
if (len(sys.argv) == 6 or len(sys.argv) == 8) and (sys.argv[1] =='auth' or sys.argv[1] == 'kick'):
	check_ip(sys.argv[2])
	check_ip(sys.argv[3])
        try:
            int(sys.argv[4])
        except ValueError:
            sys.exit(100)
	srv=Client(server=sys.argv[2], portalport=int(sys.argv[4]), dict=Dictionary("dictionary"))
else:
	usage()

try:
    if len(sys.argv) == 8 and sys.argv[1] == 'auth':
        #print "Sending reqchallenge request"
        req_challenge=srv.CreatePacket(code=pyrad.packet.ReqChallenge, userip=sys.argv[3])
        req_challenge.id = pyrad.packet.CreateID()
        req_challenge.attrnum = 0

        reply_challenge = srv.SendPacket(req_challenge)
        error_code(reply_challenge)
        
        if reply_challenge.code == pyrad.packet.AckChallenge:
            #print 'challenge ok'
            #md5_list = [chr(reply_challenge.reqid & 255), password, reply_challenge[3][0]]
            md5_list = [chr(reply_challenge.reqid & 255), sys.argv[7], reply_challenge[3][0]]
            req_auth= reply_challenge.CreateReply()
            req_auth.code = pyrad.packet.ReqAuth
            #req_auth.userip="192.168.100.3"
            req_auth.userip=sys.argv[3]
            req_auth['User-Name'] = sys.argv[6]
            req_auth["CHAP-Password"] = md5_constructor(''.join(md5_list)).digest()
            req_auth["User-Mac"] = sys.argv[5]
            req_auth.reqid = reply_challenge.reqid
            req_auth.attrnum = 3
            reply_auth = srv.SendPacket(req_auth)

            if reply_auth.errcode == 0:
            	aff_ack_auth = reply_auth.CreateReply()
            	aff_ack_auth.code = pyrad.packet.AffAckAuth
                    #aff_ack_auth.userip = "192.168.100.3"
            	aff_ack_auth.userip = sys.argv[3]
            	aff_ack_auth.reqid = reply_auth.reqid
            	aff_ack_auth.attrnum = 0
		srv.SendPacket(aff_ack_auth)
		sys.exit(0)
		#print aff_ack_auth.reqid

            	#log_out = reply_auth.CreateReply()
            	#log_out.code = pyrad.packet.ReqLogOut
            	#log_out.userip="192.168.100.3"
            	#log_out.reqid = reply_auth.reqid
            	#log_out.attrnum = 0
            	#replylogout = srv.SendPacket(log_out)
            	#if replylogout.errcode == 0:
            		#print '\nInfo: logout succeed'
            	#else:
            		#print '\nInfo: logout failed'
	    elif reply_auth.errcode == 1:
		sys.exit(1)
	    elif reply_auth.errcode == 4:
		sys.exit(1)
	    else:
		sys.exit(2)
    elif len(sys.argv) == 6 and sys.argv[1] == 'kick':
        log_out=srv.CreatePacket(code=pyrad.packet.ReqLogOut, userip=sys.argv[3])
	log_out.reqid = 1
	log_out.attrnum = 1
        log_out["User-Mac"] = sys.argv[5]
	replylogout = srv.SendPacket(log_out)

	if replylogout.errcode == 0:
		sys.exit(0)
	elif replylogout.errcode == 1:
		sys.exit(1)
	else:
		sys.exit(2)
    else:
	usage()
except pyrad.client.Timeout:
    print "AC does not reply"
    sys.exit(2)
except socket.error, error:
    print "Network error: " + error[1]
    sys.exit(2)

