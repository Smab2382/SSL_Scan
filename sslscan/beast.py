__author__ = 'Smab'

import socket
import ssl
def funbest(host):
    shif2='CBC'
    port = 443
    sock = socket.socket()
    sslsock=ssl.SSLSocket(sock)
    context = sslsock.context
    context.options=ssl.OP_NO_TLSv1_2
    context.options=ssl.OP_NO_TLSv1_1
    try:
        sslsock.connect((host, port))
    except ConnectionError:
        print("connect error")
    except ConnectionResetError:
        print("connect error")
    except ssl.SSLError:
        print("no vulnerability server-side")
    var=sslsock.cipher()
    if var!=None:
        if var[0].find(shif2,0,len(var[0]))>=0:
            print('vulnerability server-side')
        else:
            print('no vulnerability server-side')
    print(var)
    sslsock.close()

host = 'google.ru'
funbest(host)


