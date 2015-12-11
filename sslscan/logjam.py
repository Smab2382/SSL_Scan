__author__ = 'Smab'

import socket
import ssl

def funlogjam(host):
    port = 443
    sock = socket.socket()
    ssl_sock=ssl.SSLSocket(sock,do_handshake_on_connect=False)
    context=ssl_sock.context
    print(ssl_sock.cipher())
    try:
        ssl_sock.connect((host, port))
        print(ssl_sock.cipher())
        try:
            context.set_ciphers('EXP-EDH-RSA-DES-CBC-SHA:+EXP-EDH-DSS-DES-CBC-SHA:+EXP-ADH-DES-CBC-SHA:+EXP-ADH-RC4-MD5')
            ssl_sock.do_handshake()
            print(ssl_sock.cipher())
        except ssl.SSLError:
            print("no vulnerability server-side")
        else:
            print("vulnerability server-side")
    except ConnectionError:
        print("connect error")
    except ConnectionResetError:
        print("connect error")
    except ssl.SSLError:
        print("no vulnerability server-side")
    ssl_sock.close()

funlogjam("insidesecure.com")