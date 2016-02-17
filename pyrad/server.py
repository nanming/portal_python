# server.py
#
# Copyright 2003-2004,2007 Wichert Akkerman <wichert@wiggy.net>

import select
import socket
from pyrad import host
from pyrad import packet
import logging
import struct


logger = logging.getLogger('pyrad')


class RemoteHost:
    """Remote RADIUS capable host we can talk to.
    """

    def __init__(self, address, name, port=2000):
        """Constructor.

        :param   address: IP address
        :type    address: string
        :param    secret: RADIUS secret
        :type     secret: string
        :param      name: short name (used for logging only)
        :type       name: string
        :param  authport: port used for authentication packets
        :type   authport: integer
        :param  acctport: port used for accounting packets
        :type   acctport: integer
        """
        self.address = address
        self.port = port
        self.name = name


class ServerPacketError(Exception):
    """Exception class for bogus packets.
    ServerPacketError exceptions are only used inside the Server class to
    abort processing of a packet.
    """


class Server(host.Host):
    """Basic RADIUS server.
    This class implements the basics of a RADIUS server. It takes care
    of the details of receiving and decoding requests; processing of
    the requests should be done by overloading the appropriate methods
    in derived classes.

    :ivar  hosts: hosts who are allowed to talk to us
    :type  hosts: dictionary of Host class instances
    :ivar  _poll: poll object for network sockets
    :type  _poll: select.poll class instance
    :ivar _fdmap: map of filedescriptors to network sockets
    :type _fdmap: dictionary
    :cvar MaxPacketSize: maximum size of a RADIUS packet
    :type MaxPacketSize: integer
    """

    MaxPacketSize = 1024

    def __init__(self, addresses=[], port=2000, hosts=None,
            dict=None):
        """Constructor.

        :param addresses: IP addresses to listen on
        :type  addresses: sequence of strings
        :param  authport: port to listen on for authentication packets
        :type   authport: integer
        :param  acctport: port to listen on for accounting packets
        :type   acctport: integer
        :param     hosts: hosts who we can talk to
        :type      hosts: dictionary mapping IP to RemoteHost class instances
        :param      dict: RADIUS dictionary to use
        :type       dict: Dictionary class instance
        """
        host.Host.__init__(self, port, dict)
        if hosts is None:
            self.hosts = {}
        else:
            self.hosts = hosts

        self.sockfds = []

        for addr in addresses:
            self.BindToAddress(addr)

    def BindToAddress(self, addr):
        """Add an address to listen to.
        An empty string indicated you want to listen on all addresses.

        :param addr: IP address to listen on
        :type  addr: string
        """
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	#sockfd.bind((addr, 2000))
	sockfd.bind(('0.0.0.0', 50100))

        self.sockfds.append(sockfd)
        #self.acctfds.append(acctfd)

    def HandlePacket(self, pkt):
        """Authentication packet handler.
        This is an empty function that is called when a valid
        authentication packet has been received. It can be overriden in
        derived classes to add custom behaviour.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """

    def _HandlePacket(self, pkt):
        """Process a packet received on the authentication port.
        If this packet should be dropped instead of processed a
        ServerPacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        :param pkt: packet to process
        :type  pkt: Packet class instance
        """
        #if pkt.source[0] not in self.hosts:
            #raise ServerPacketError('Received packet from unknown host')

        self.HandlePacket(pkt)

    def _GrabPacket(self, pktgen, fd):
        """Read a packet from a network connection.
        This method assumes there is data waiting for to be read.

        :param fd: socket to read packet from
        :type  fd: socket class instance
        :return: RADIUS packet
        :rtype:  Packet class instance
        """
        (data, source) = fd.recvfrom(self.MaxPacketSize)
        pkt = pktgen(data)
        pkt.source = source
        pkt.fd = fd
        return pkt

    def _PrepareSockets(self):
        """Prepare all sockets to receive packets.
        """
        for fd in self.sockfds:
            self._fdmap[fd.fileno()] = fd
            self._poll.register(fd.fileno(),
                    select.POLLIN | select.POLLPRI | select.POLLERR)
        self._realauthfds = list(map(lambda x: x.fileno(), self.sockfds))

    def CreateReplyPacket(self, pkt, **attributes):
        """Create a reply packet.
        Create a new packet which can be returned as a reply to a received
        packet.

        :param pkt:   original packet
        :type pkt:    Packet instance
        """
        reply = pkt.CreateReply(**attributes)
        reply.source = pkt.source
        return reply

    def _ProcessInput(self, fd):
        """Process available data.
        If this packet should be dropped instead of processed a
        PacketError exception should be raised. The main loop will
        drop the packet and log the reason.

        This function calls either HandleAuthPacket() or
        HandleAcctPacket() depending on which socket is being
        processed.

        :param  fd: socket to read packet from
        :type   fd: socket class instance
        """
        pkt = self._GrabPacket(lambda data, s=self:
	    s.CreatePacket(packet=data), fd)
	#print pkt.code, pkt.ver, socket.inet_ntoa(struct.pack('!I',pkt.userip)), pkt.chap
	self._HandlePacket(pkt)
	#print '_ProcessInput'

    def Run(self):
        """Main loop.
        This method is the main loop for a RADIUS server. It waits
        for packets to arrive via the network and calls other methods
        to process them.
        """
        self._poll = select.poll()
        self._fdmap = {}
        self._PrepareSockets()

        while 1:
            for (fd, event) in self._poll.poll():
                if event == select.POLLIN:
                    try:
                        fdo = self._fdmap[fd]
                        self._ProcessInput(fdo)
                    except ServerPacketError as err:
                        logger.info('Dropping packet: ' + str(err))
                    except packet.PacketError as err:
                        logger.info('Received a broken packet: ' + str(err))
                else:
                    logger.error('Unexpected event in server main loop')
