__author__ = 'Smab'

import socket
import ssl
def funbest(host):
    port = 443
    sock = socket.socket()
    ssl_sock=ssl.SSLSocket(sock)
    context = ssl_sock.context
    context.options=ssl.OP_NO_TLSv1_2
    context.options=ssl.OP_NO_TLSv1_1
    context.set_ciphers('DES-CBC3-SHA:+DH-DSS-DES-CBC3-SHA:+DH-DSS-DES-CBC3-SHA:+DH-RSA-DES-CBC3-SHA:+SEED:+CAMELLIA:'
                        '+DHE-DSS-DES-CBC3-SHA:+DHE-RSA-DES-CBC3-SHA:+ADH-DES-CBC3-SHA:+AES')
    try:
        ssl_sock.connect((host, port))
    except ConnectionError:
        print("connect error")
    except ConnectionResetError:
        print("connect error")
    except ssl.SSLError:
        print("no vulnerability server-side")
    else:
        print("vulnerability server-side")
    ssl_sock.close()

def main(): #for test
    host = 'google.ru'
    funbest(host)

if __name__ == '__main__':
    main()

