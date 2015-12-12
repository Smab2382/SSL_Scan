import urllib.parse
import socket
from OpenSSL import SSL


def check(host, port=443):
    print("Start scan: {0} at port {1}".format(host, port))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Connecting...')
    context = SSL.Context(SSL.TLSv1_METHOD)
    context.set_options(SSL.OP_NO_SSLv2)
    context.set_cipher_list('EXPORT')
    ssl_sock = SSL.Connection(context, s)
    try:
        ssl_sock.connect((host, port))
        try:
            ssl_sock.do_handshake()
        except SSL.Error:
            print("NOT VULNERABLE")
        else:
            print("VULNERABLE")
    except:
        ssl_sock.close()
        print("Failed to connect")


def main(): #for test
    url = "https://insidesecure.com"
    host = urllib.parse.urlparse(url).netloc
    check(host)

if __name__ == '__main__':
    main()