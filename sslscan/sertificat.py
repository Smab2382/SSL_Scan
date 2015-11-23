#!/usr/bin/python3
__author__ = 'hulponot'

import socket, ssl, pprint, re

def cert_info(hostname):
    
    protocols = (ssl.PROTOCOL_SSLv2, ssl.PROTOCOL_SSLv3, ssl.PROTOCOL_SSLv23, ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2)

    for p in protocols:
        context = ssl.SSLContext(p)
        context.load_default_certs()
        context.verify_mode = ssl.CERT_REQUIRED
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        try:
            conn.connect((hostname,443))
            cert = conn.getpeercert()
            #pprint.pprint (cert)
        except ConnectionResetError:
            print ("connection refused with ",resolve_to_protocol_string(p))
        except ssl.SSLError:
            print ("handshake or so refused with ",resolve_to_protocol_string(p))
    dateBefore = cert["notBefore"]
    date = re.split(' +', dateBefore)
    monthB = date[0]
    yearB = date[3]
    dayB = date[1]
    (hourB,minuteB,secB) = re.split(':', date[2])
    print (hourB)
    dateAfter = cert["notAfter"]


def resolve_to_protocol_string(protocol_int):
    if (protocol_int == 0):
        return ("PROTOCOL_SSLv2")
    if (protocol_int == 1):
        return "PROTOCOL_SSLv3"
    if (protocol_int == 2):
        return "PROTOCOL_SSLv23"
    if (protocol_int == 3):
        return "PROTOCOL_TSLv1"
    if (protocol_int == 4):
        return "PROTOCOL_TSLv1.1"
    if (protocol_int == 5):
        return "PROTOCOL_TSLv1.2"


cert_info('www.python.org')
