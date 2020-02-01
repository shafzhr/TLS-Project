import socket
import struct 
import functools 

CERTIFICATES = ["c1.ssl", "c2.ssl"]

def ServerHello(session_ID, SSL_version="\x03\x03"):
    """
    This method forms the ServerHelloDone message
    """
    content_type = "\x16" #Handshake
    version = SSL_version
    #Length

    handshake_type = "\x02" #ServerHello
    #Length

    version = SSL_version    
    server_random = -1
    session_ID_length = len(session_ID)
    #session_ID = -1
    cipher_suite = -1 #(Choose Cipher Suite)
    compression_method = 0
    #extensions_length
    #extensions

    msg = version + server_random + session_ID_length + session_ID \
            + cipher_suite + compression_method
    msg = short(len(msg)) + msg
    msg = handshake_type + msg
    msg = int_3_bytes(len(msg)) + msg
    msg = content_type + version + msg
    return msg


def int_3_bytes(seq):
    return struct.pack('!i', seq)[1:]


def short(seq):
    return struct.pack('!h', seq)


def Certificate(SSL_version="\x03\x03"):
    """
    This method forms certificate msg, 
    reading the certificate content from a given file.
    """
    #Preparation
    certificates = []
    for c in CERTIFICATES:
        with open(c) as f:
            certificates.append(f.readbytes())

    certificates = map(lambda x: int_3_bytes(len(x)) + x, certificates)
    
    #Message Fields
    content_type = "\x16" #Handshake
    version = SSL_version
    #Length short

    handshake_type = "\x0b" #Certificate
    #Length 3 bytes

    certificates_length = int_3_bytes(sum([len(i) for i in certificates]))

    #Forming Message:
    msg = certificates_length + functools.reduce(lambda x, y: x + y, certificates)
    msg = int_3_bytes(len(msg)) + msg
    msg = handshake_type + msg
    msg = short(len(msg)) + msg
    msg = content_type + version + msg
    
    return msg
    
