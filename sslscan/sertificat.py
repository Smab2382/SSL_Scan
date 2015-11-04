#!/usr/bin/python
__author__ = 'hulponot'

import socket, ssl, pprint

def cert_info(hostname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(sock);
    ssl_sock.connect((hostname, 443))
    pprint.pprint(ssl_sock.getpeercert(0))
    pprint.pprint(ssl_sock.cipher())

    pprint.pprint(ssl_sock.version())

    ssl_sock.close()
    sock.close()

cert_info('vk.com')
