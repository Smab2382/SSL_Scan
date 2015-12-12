__author__ = 'kowalskiAG'

import socket, ssl
from sslscan import status


def poodlefun(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock=ssl.SSLSocket(s)
    context = ssl_sock.context
    context.options=ssl.OP_NO_TLSv1
    try:
        ssl_sock.connect((host, 443))
    except ConnectionError:
        print("connect error")
        return status.Status.stError
    except ConnectionResetError:
        print("connect error")
        return status.Status.stError
    except ssl.SSLError:
        print("NO VULNERABLE")
        return status.Status.stOk
    else:
        print("VULNERABLE")
        return status.Status.stVuln

def main():
    host = 'www.google.com'
    poodlefun(host)

if __name__ == '__main__':
    main()
