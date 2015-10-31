__author__ = 'Smab'

import socket
import ssl

shif1='AES128-SHA'
shif2='CBC'
host = 'support.bfb-ev.de'
port = 443
sert=ssl.get_server_certificate((host, port),ssl.PROTOCOL_TLSv1,None)
sock = socket.socket()
sslsock=ssl.SSLSocket(sock)
sslsock.connect((host, port))
var=sslsock.cipher()
b=True
if var[0].find(shif2,0,len(var[0]))>=0:
    print('vulnerability server-side')
    b=False
else:
    if var[0].find(shif1,0,len(var[0]))>=0:
        print('mitigated server-side')
        b=False
if b:
    print('no mitigated server-side')
print(var)



