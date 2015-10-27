__author__ = 'Den'

import socket
import sys
import binascii
import time
import select
import struct
import urllib.parse

#binary string from hex string
def hex2bin(x):
    return binascii.unhexlify(x.replace(' ', '').replace('\n', ''))

#packet with hello message we want to send
helloPacket = hex2bin(
'16 03 02 00 31'    # Content type = 16 (handshake message); Version = 03 02; Packet length = 00 31
'01 00 00 2d'       # Message type = 01 (client hello); Length = 00 00 2d

'03 02'             # Client version = 03 02 (TLS 1.1)

# Random (uint32 time followed by 28 random bytes):
'50 0b af bb b7 5a b8 3e f0 ab 9a e3 f3 9c 63 15 33 41 37 ac fd 6c 18 1a 24 60 dc 49 67 c2 fd 96'
'00'                # Session id = 00
'00 04 '            # Cipher suite length
'00 33 c0 11'       # 4 cipher suites
'01'                # Compression methods length
'00'                # Compression method 0: no compression = 0
'00 00'             # Extensions length = 0
)

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

def check(url, port=443):
    host = urllib.parse.urlparse(url).netloc
    print("Start scan: {0} at port {1}".format(host, port))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('Connecting...')
    s.connect((host, port))

    print('Sending Client Hello...')
    s.send(helloPacket)

    print('Waiting for Server Hello...')

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

def main(): #for test
	check("fitnessland.spb.ru")

if __name__ == '__main__':
	main()