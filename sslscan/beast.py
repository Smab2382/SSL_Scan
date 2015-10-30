__author__ = 'Smab'

import socket
import ssl

host = 'mts.ru'
port = 443
sert=ssl.get_server_certificate((host, port),ssl.PROTOCOL_TLSv1,None)
sock = socket.socket()
sslsock=ssl.SSLSocket(sock)
sslsock.connect((host, port))
var=sslsock.cipher()
print(var[0])



