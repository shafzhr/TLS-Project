import struct
import secrets
# from tls13.handshake_headers import NewSessionTicketHandshakePayload
import hmac
import hashlib
import binascii


EXTENSION_SERVER_NAME = 0x00
EXTENSION_SUPPORTED_GROUPS = 0x0A
EXTENSION_SIGNATURE_ALGORITHMS = 0x0D
EXTENSION_KEY_SHARE = 0x33
EXTENSION_PSK_KEY_EXCHANGE_MODES = 0x2D
EXTENSION_SUPPORTED_VERSIONS = 0x2B
EXTENSION_EARLY_DATA = 0x2A
EXTENSION_PRE_SHARED_KEY = 0x29


def RecordHeader(rtype, legacy_protocol_version=0x0301, size=0):
    return ""

def HandshakeHeader(message_type, size):
    return ""


class ClientHello:
    def __init__(self, domain: bytes, public_key_bytes: bytes):
        self.record_header = RecordHeader(rtype=0x16, legacy_protocol_version=0x0301, size=0)
        self.handshake_header = HandshakeHeader(message_type=0x01, size=0)
        self.client_version = 0x0303
        self.client_random = secrets.token_bytes(32)
        self.session_id = secrets.token_bytes(32)
        #cipher suits:
        # 13 01 - assigned value for TLS_AES_128_GCM_SHA256
        # 13 02 - assigned value for TLS_AES_256_GCM_SHA384
        # 13 03 - assigned value for TLS_CHACHA20_POLY1305_SHA256
        self.cipher_suites = bytes.fromhex("130113021303")

        self.extensions = [
            
        ]

    def add_extension(self, extension):
        self.extensions.append(extension)
    

