__author__ = 'Smab'

import socket
import ssl

def funlogjam(host):
    shif2='DH'
    port = 443
    sock = socket.socket()
    sslsock=ssl.SSLSocket(sock)
    context=sslsock.context
    try:
        sslsock.connect((host, port))
    except ConnectionError:
        print("connect error")
    except ConnectionResetError:
        print("connect error")
    var=sslsock.cipher()
    if var!=None:
        if var[0].find(shif2,0,len(var[0]))>=0:
            context.set_ciphers('EXPORT')
            b=True
            try:
                sslsock.do_handshake((host, port))
            except ssl.SSLError:
                print("no vulnerability server-side")
                b=False
            if b: print("vulnerability server-side")
    print(var)
    sslsock.close()

funlogjam("yandex.ru")