__author__ = 'kowalskiAG'

import socket, ssl

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock=ssl.SSLSocket(s)
context = ssl_sock.context
context.options=ssl.OP_NO_TLSv1_2
context.options=ssl.OP_NO_TLSv1_1
context.options=ssl.OP_NO_TLSv1
try:
    ssl_sock.connect(('www.google.com', 443))
except ConnectionResetError:
    print("fu")
    print("no")
print(ssl_sock.version())
ssl_sock.close()