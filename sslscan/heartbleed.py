__author__ = 'Den'

import socket
import sys
import binascii
import time
import select
import struct

#binary string from hex string
def hex2bin(x):
    return binascii.unhexlify(x.replace(' ', '').replace('\n', ''))

#packet with hello message we want to send
helloPacket = hex2bin('4f 3b')

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = b''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        # Wait until the socket is ready to be read
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata

def getTLSMessage(s, fragments=1):
    contentType = None
    version = None
    length = None
    payload = b''

    # The server may send less fragments. Because of that, this will return partial data.
    for fragmentIndex in range(0, fragments):
        tlsHeader = recvall(s, 5) # Receive 5 byte header (Content type, version, and length)

        if tlsHeader is None:
            print('Unexpected EOF receiving record header - server closed connection')
            return contentType, version, payload # Return what we currently have

        contentType, version, length = struct.unpack('>BHH', tlsHeader) # Unpack the header
        payload_tmp = recvall(s, length, 5) # Receive the data that the server told us it'd send

        if payload_tmp is None:
            print('Unexpected EOF receiving record payload - server closed connection')
            return contentType, version, payload # Return what we currently have

        print('Received message: type = %d, ver = %04x, length = %d' % (contentType, version, len(payload_tmp)))

        payload = payload + payload_tmp

    return contentType, version, payload

def check(host, port=443):
    print("Start scan: {0} at port {1}".format(host, port))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Connecting...')
    sys.stdout.flush()
    s.connect((host, port))
    print('Sending Client Hello...')
    sys.stdout.flush()
    s.send(helloPacket)
    print('Waiting for Server Hello...')
    sys.stdout.flush()

    # Receive packets until we get a hello done packet
    while True:
        contentType, version, payload = getTLSMessage(s)
        if contentType == None:
            print('Server closed connection without sending Server Hello.')
            return
        # Look for server hello done message.
        if contentType == 22 and payload[0] == 0x0E:
            break

    print('Sending heartbeat request...')
    sys.stdout.flush()

def main(): #for test
	check("fitnessland.spb.ru")

if __name__ == '__main__':
	main()