__author__ = 'Elena'

try:
import ssl
except ImportError:
pass
Else:
import socket, ssl, pprint

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

ssl_sock = ssl.wrap_socket(s, ca_certs="/etc/ca_certs_file", cert_reqs=ssl.CERT_REQUIRED)
ssl_sock.connect(('www.google.com', 443))

pprint.pprint(ssl_sock.getpeercert())

ssl_sock.close()
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.verify_mode = ssl.CERT_REQUIRED