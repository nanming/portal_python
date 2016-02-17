# packet.py
#
# Copyright 2002-2005,2007 Wichert Akkerman <wichert@wiggy.net>
#
# A RADIUS packet as defined in RFC 2138


import struct
import random
import sys
import socket
try:
    import hashlib
    md5_constructor = hashlib.md5
except ImportError:
    # BBB for python 2.4
    import md5
    md5_constructor = md5.new
import six
from pyrad import tools
from pyrad import dictionary

# Packet codes
ReqChallenge = 0x01
AckChallenge = 0x02
ReqAuth = 0x03
AckAuth = 0x04
ReqLogOut = 0x05
AckLogOut = 0x06
AffAckAuth = 0x07
NtfLogOut = 0x08
ReqInfo = 0x09
AckInfo = 0x0a

# Current ID
CurrentID = random.randrange(1, 255)


class PacketError(Exception):
    pass


class Packet(dict):
    """Packet acts like a standard python map to provide simple access
    to the Portal attributes. Since Portal allows for repeated
    attributes the value will always be a sequence. pyrad makes sure
    to preserve the ordering when encoding and decoding packets.

    There are two ways to use the map intereface: if attribute
    names are used pyrad take care of en-/decoding data. If
    the attribute type number (or a vendor ID/attribute type
    tuple for vendor attributes) is used you work with the
    raw data.

    """

    def __init__(self, ver=1, code=0, userip=None, id=0, userport=0,
	    errcode=0, reqid=0, attrnum=0, **attributes):
        """Constructor
        """
        dict.__init__(self)
        self.code = code 
	self.ver = ver
	self.rsv = 0
	self.userip = userip
	self.userport = userport
	self.errcode = errcode
	self.reqid = reqid
	self.attrnum = attrnum
	if self.code == 3:
	    self.chap = 1
	else:
	    self.chap = 0

	if id is not None:
	    self.id = id
	else:
	    self.id = CreateID()

	if 'dict' in attributes:
	    self.dict = attributes['dict']

        if 'packet' in attributes:
	    self.DecodePacket(attributes['packet'])

	for (key, value) in attributes.items():
	    if key in ['dict', 'fd', 'packet']:
		continue
	    key = key.replace('_', '-')
	    self.AddAttribute(key, value)

    def CreateReply(self, **attributes):
	"""Create a new packet as a reply to this one
	"""
	return Packet(ver=self.ver, userip=self.userip, id=self.id,
			userport=self.userport, dict=self.dict, **attributes)

    def _DecodeValue(self, attr, value):
	if attr.values.HasBackward(value):
	    return attr.values.GetBackward(value)
	else:
	    return tools.DecodeAttr(attr.type, value)

    def _EncodeValue(self, attr, value):
	if attr.values.HasForward(value):
	    return attr.values.GetForward(value)
	else:
	    return tools.EncodeAttr(attr.type, value)

    def _EncodeKeyValues(self, key, values):
	if not isinstance(key, str):
	    return (key, values)

	attr = self.dict.attributes[key]
	if attr.vendor:
	    key = (self.dict.vendors.GetForward(attr.vendor), attr.code)
	else:
	    key = attr.code

	return (key, [self._EncodeValue(attr, v) for v in values])

    def _EncodeKey(self, key):
	if not isinstance(key, str):
	    return key

	attr = self.dict.attributes[key]
	if attr.vendor:
	    return (self.dict.vendors.GetForward(attr.vendor), attr.code)
	else:
	    return attr.code

    def _DecodeKey(self, key):
	"""Turn a key into a string if possible"""

	if self.dict.attrindex.HasBackward(key):
	    return self.dict.attrindex.GetBackward(key)
	return key

    def AddAttribute(self, key, value):
	"""Add an attribute to the packet.

	:param key:   attribute name or identification
	:type key:    string, attribute code or (vendor code, attribute code)
		      tuple
	:param value: value
	:type value:  depends on type of attribute
	"""
	(key, value) = self._EncodeKeyValues(key, [value])
	value = value[0]

	self.setdefault(key, []).append(value)

    def __getitem__(self, key):
	if not isinstance(key, six.string_types):
	    return dict.__getitem__(self, key)

	values = dict.__getitem__(self, self._EncodeKey(key))
	attr = self.dict.attributes[key]
	res = []
	for v in values:
	    res.append(self._DecodeValue(attr, v))
	return res

    def __contains__(self, key):
	try:
	    return dict.__contains__(self, self._EncodeKey(key))
	except KeyError:
	    return False

    has_key = __contains__

    def __delitem__(self, key):
	dict.__delitem__(self, self._EncodeKey(key))

    def __setitem__(self, key, item):
	if isinstance(key, six.string_types):
	    (key, item) = self._EncodeKeyValues(key, [item])
	    dict.__setitem__(self, key, item)
	else:
	    assert isinstance(item, list)
	    dict.__setitem__(self, key, item)

    def keys(self):
	return [self._DecodeKey(key) for key in dict.keys(self)]

    @staticmethod
    def CreateAuthenticator():
	"""Create a packet autenticator. All RADIUS packets contain a sixteen
	byte authenticator which is used to authenticate replies from the
	RADIUS server and in the password hiding algorithm. This function
	returns a suitable random string that can be used as an authenticator.

	:return: valid packet authenticator
	:rtype: binary string
	"""

	data = []
	for i in range(16):
	    data.append(random.randrange(0, 256))
	if six.PY3:
	    return bytes(data)
	else:
	    return ''.join(chr(b) for b in data)

    def CreateID(self):
	"""Create a packet ID.  All RADIUS requests have a ID which is used to
	identify a request. This is used to detect retries and replay attacks.
	This function returns a suitable random number that can be used as ID.

	:return: ID number
	:rtype:  integer

	"""
	return random.randrange(0, 256)

    def ReplyPacket(self):
	"""Create a ready-to-transmit authentication reply packet.
	Returns a RADIUS packet which can be directly transmitted
	to a RADIUS server. This differs with Packet() in how
	the authenticator is calculated.

	:return: raw packet
	:rtype:  string
	"""
	#assert(self.authenticator)
	#assert(self.secret)

	attr = self._PktEncodeAttributes()

	header = struct.pack("!4B2HIH2B", self.ver, self.code, self.chap, self.rsv,
		self.id, self.reqid, self.userip, self.userport, self.errcode, self.attrnum)

	#authenticator = md5_constructor(header[0:4] + self.authenticator
			      #+ attr + self.secret).digest()
	return header + attr

    def VerifyReply(self, reply, rawreply=None):
	if reply.id != self.id:
	    return False

	if rawreply is None:
	    rawreply = reply.ReplyPacket()

	#hash = md5_constructor(rawreply[0:4] + self.authenticator +
		     #rawreply[20:] + self.secret).digest()

	#if hash != rawreply[4:20]:
	    #return False
	return True

    def _PktEncodeAttribute(self, key, value):
	if isinstance(key, tuple):
	    value = struct.pack('!L', key[0]) + \
		self._PktEncodeAttribute(key[1], value)
	    key = 26

	return struct.pack('!BB', key, (len(value) + 2)) + value

    def _PktEncodeAttributes(self):
	result = six.b('')
	for (code, datalst) in self.items():
	    for data in datalst:
		result += self._PktEncodeAttribute(code, data)

	return result

    #def _PktDecodeVendorAttribute(self, data):
	## Check if this packet is long enough to be in the
	## RFC2865 recommended form
	#if len(data) < 6:
	    #return (26, data)

	#(vendor, type, length) = struct.unpack('!LBB', data[:6])[0:3]
	## Another sanity check
	#if len(data) != length + 4:
	    #return (26, data)

	#return ((vendor, type), data[6:])

    def DecodePacket(self, packet):
	"""Initialize the object from raw packet data.  Decode a packet as
	received from the network and decode it.

	:param packet: raw packet
	:type packet:  string"""

	try:

            (self.ver, self.code, self.chap, self.rsv, self.id, self.reqid, self.userip, self.userport, self.errcode, self.attrnum) = \
                        struct.unpack("!4B2HIH2B", packet[0:16])
	except struct.error:
	    raise PacketError('Packet header is corrupt')
	#if len(packet) != length:
	    #raise PacketError('Packet has invalid length')
	#if length > 8192:
	    #raise PacketError('Packet length is too long (%d)' % length)

	self.clear()

	packet = packet[16:]
	while packet:
	    try:
		(key, attrlen) = struct.unpack('!BB', packet[0:2])
	    except struct.error:
		raise PacketError('Attribute header is corrupt')

	    if attrlen < 2:
		raise PacketError(
			'Attribute length is too small (%d)' % attrlen)

	    value = packet[2:attrlen]
	    #if key == 26:
		#(key, value) = self._PktDecodeVendorAttribute(value)

	    self.setdefault(key, []).append(value)
	    packet = packet[attrlen:]

    def RequestPacket(self):
	"""Create a ready-to-transmit authentication request packet.
	Return a RADIUS packet which can be directly transmitted
	to a RADIUS server.

	:return: raw packet
	:rtype:  string
	"""
	attr = self._PktEncodeAttributes()

	userip = struct.unpack("!I",socket.inet_aton(self.userip))[0]
	#print 'self.ver=%d, self.code=%d, self.chap=%d, self.rsv=%d, self.id=%d, self.reqid=%d, self.userip=%s, self.userport=%d, self.errcode=%d, self.attnum=%d' %(self.ver, self.code, self.chap, self.rsv, self.id, self.reqid, self.userip, self.userport, self.errcode, self.attrnum)
	header = struct.pack("!4B2HIH2B", self.ver, self.code, self.chap, self.rsv,
		self.id, self.reqid, userip, self.userport, self.errcode, self.attrnum)

	return header + attr

    def PwDecrypt(self, password):
	"""Unobfuscate a RADIUS password. RADIUS hides passwords in packets by
	using an algorithm based on the MD5 hash of the packet authenticator
	and RADIUS secret. This function reverses the obfuscation process.

	:param password: obfuscated form of password
	:type password:  binary string
	:return:         plaintext password
	:rtype:          unicode string
	"""
	buf = password
	pw = six.b('')

	last = self.authenticator
	while buf:
	    hash = md5_constructor(self.secret + last).digest()
	    if six.PY3:
		for i in range(16):
		    pw += bytes((hash[i] ^ buf[i],))
	    else:
		for i in range(16):
		    pw += chr(ord(hash[i]) ^ ord(buf[i]))

	    (last, buf) = (buf[:16], buf[16:])

	while pw.endswith(six.b('\x00')):
	    pw = pw[:-1]

	return pw.decode('utf-8')

    def PwCrypt(self, password):
	"""Obfuscate password.
	RADIUS hides passwords in packets by using an algorithm
	based on the MD5 hash of the packet authenticator and RADIUS
	secret. If no authenticator has been set before calling PwCrypt
	one is created automatically. Changing the authenticator after
	setting a password that has been encrypted using this function
	will not work.

	:param password: plaintext password
	:type password:  unicode stringn
	:return:         obfuscated version of the password
	:rtype:          binary string
	"""
	if self.authenticator is None:
	    self.authenticator = self.CreateAuthenticator()

	if isinstance(password, six.text_type):
	    password = password.encode('utf-8')

	buf = password
	if len(password) % 16 != 0:
	    buf += six.b('\x00') * (16 - (len(password) % 16))

	hash = md5_constructor(self.secret + self.authenticator).digest()
	result = six.b('')

	last = self.authenticator
	while buf:
	    hash = md5_constructor(self.secret + last).digest()
	    if six.PY3:
		for i in range(16):
		    result += bytes((hash[i] ^ buf[i],))
	    else:
		for i in range(16):
		    result += chr(ord(hash[i]) ^ ord(buf[i]))

	    last = result[-16:]
	    buf = buf[16:]

	return result

def CreateID():
    """Generate a packet ID.

    :return: packet ID
    :rtype:  8 bit integer
    """
    global CurrentID

    #CurrentID = (CurrentID + 1) % 256
    CurrentID = (CurrentID + 1) % 65536
    return CurrentID
