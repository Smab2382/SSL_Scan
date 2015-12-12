__author__ = 'Smab'

import socket
import ssl
from sslscan import status

def funlogjam(host):
    port = 443
    sock = socket.socket()
    ssl_sock=ssl.SSLSocket(sock,do_handshake_on_connect=False)
    context=ssl_sock.context
    try:
        ssl_sock.connect((host, port))
        print(ssl_sock.cipher())
        try:
            context.set_ciphers('EXP-EDH-RSA-DES-CBC-SHA:+EXP-EDH-DSS-DES-CBC-SHA:+EXP-ADH-DES-CBC-SHA:+EXP-ADH-RC4-MD5')
            ssl_sock.do_handshake()
        except ssl.SSLError:
            print("NO VULNERABLE")
            return status.Status.stOk
        else:
            print("VULNERABLE")
            return status.Status.stVuln
    except ConnectionError:
        print("connect error")
        return status.Status.stError
    except ConnectionResetError:
        print("connect error")
        return status.Status.stError
    ssl_sock.close()

def main(): #for test
    host = "insidesecure.com"
    funlogjam(host)

if __name__ == '__main__':
    main()