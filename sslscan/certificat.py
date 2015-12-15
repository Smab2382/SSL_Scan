#!/usr/bin/python3
__author__ = 'hulponot'

import socket, ssl, pprint, re
import time
from sslscan import status

def cert_info(hostname):
    
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.load_default_certs()
    context.verify_mode = ssl.CERT_REQUIRED
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    cert = 0;
    try:
        conn.connect((hostname,443))
        cert = conn.getpeercert()
    except ConnectionResetError:
        print ("connection refused with ",resolve_to_protocol_string(p))
        return status.Status.stError
    except ssl.SSLError:
        print ("handshake or so refused with ",resolve_to_protocol_string(p))
        return status.Status.stError
    if cert == 0:
        return status.Status.stUnknown
    pprint.pprint(cert)
    dateBefore = cert["notBefore"]
    #print (dateBefore,"\n")
    date = re.split(' +', dateBefore)
    monthB = date[0]
    yearB = date[3]
    dayB = date[1]
    (hourB,minuteB,secB) = re.split(':', date[2])

    dateAfter = cert["notAfter"]
    #print (dateAfter,"\n")
    date = re.split(' +', dateBefore)
    monthB = date[0]
    yearB = date[3]
    dayB = date[1]
    (hourB,minuteB,secB) = re.split(':', date[2])
    #print (time.strftime("%b %d %H:%M:%S %Y %Z", time.gmtime()))
    #print (ssl.cert_time_to_seconds(dateBefore),"\n",ssl.cert_time_to_seconds(dateBefore))
    #print(ssl.cert_time_to_seconds(time.strftime("%b %d %H:%M:%S %Y %Z", time.gmtime())))
    
    
def ssl2av(hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv2)
    context.load_default_certs()
    context.verify_mode = ssl.CERT_REQUIRED
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    cert = 0;
    try:
        conn.connect((hostname,443))
        cert = conn.getpeercert()
    except ConnectionResetError:
        print ("connection refused with SSL2")
        return status.Status.stError
    except ssl.SSLError:
        print ("handshake or so refused with SSL2")
        return status.Status.stError
    if cert == 0:
        return status.Status.stUnknown
    print ("SSL 2 working fine")
    return status.Status.stOk
        
def ssl3av(hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
    context.load_default_certs()
    context.verify_mode = ssl.CERT_REQUIRED
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    cert = 0;
    try:
        conn.connect((hostname,443))
        cert = conn.getpeercert()
    except ConnectionResetError:
        print ("connection refused with SSL3")
        return status.Status.stError
    except ssl.SSLError:
        print ("handshake or so refused with SSL3")
        return status.Status.stError
    if cert == 0:
        return status.Status.stUnknown
    print ("SSL 3 working fine")
    return status.Status.stOk

def tlsav(hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    context.load_default_certs()
    context.verify_mode = ssl.CERT_REQUIRED
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    cert = 0;
    try:
        conn.connect((hostname,443))
        cert = conn.getpeercert()
    except ConnectionResetError:
        print ("connection refused with TLS 1.0")
        return status.Status.stError
    except ssl.SSLError:
        print ("handshake or so refused with TLS 1.0")
        return status.Status.stError
    if cert == 0:
        return status.Status.stUnknown
    print ("TLS 1.0 working fine")
    return status.Status.stOk
    
def tls11av(hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    context.load_default_certs()
    context.verify_mode = ssl.CERT_REQUIRED
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    cert = 0;
    try:
        conn.connect((hostname,443))
        cert = conn.getpeercert()
    except ConnectionResetError:
        print ("connection refused with TLS 1.0")
        return status.Status.stError
    except ssl.SSLError:
        print ("handshake or so refused with TLS 1.0")
        return status.Status.stError
    if cert == 0:
        return status.Status.stUnknown
    print ("TLS 1.1 working fine")
    return status.Status.stOk
    
def tls12av(hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_default_certs()
    context.verify_mode = ssl.CERT_REQUIRED
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    cert = 0;
    try:
        conn.connect((hostname,443))
        cert = conn.getpeercert()
    except ConnectionResetError:
        print ("connection refused with TLS 1.0")
        return status.Status.stError
    except ssl.SSLError:
        print ("handshake or so refused with TLS 1.0")
        return status.Status.stError
    if cert == 0:
        return status.Status.stUnknown
    print ("TLS 1.2 working fine")
    return status.Status.stOk  
def main(): #for test
    host = 'www.python.org'
    cert_info(host)

if __name__ == '__main__':
    main()
