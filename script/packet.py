from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from meshtastic import mesh_pb2

from packetdata import PacketData
from message import Message
from util import msb2lsb, hex_to_binary, b64_to_hex

class Packet(object):
    def __init__(self, packet):
        ## Timestamp of the packet
        self.timestamp = datetime.now()

        ## Set raw
        self.raw = packet

        ## Parse raw into data structure
        self.packet = PacketData(self.raw)
        self.src = self.packet.get_source()
        self.dest = self.packet.get_dest()
        self.packet_id = self.packet.get_packet_id()
        self.flags = self.packet.get_flags()
        self.channel_hash = self.packet.get_channel_hash()
        self.reserved = self.packet.get_reserved()
        self.data = self.packet.get_data()

    def get_raw(self):
        if hasattr(self, "raw"):
            return self.raw
        else:
            return None
        
    def get_timestamp(self):
        if hasattr(self, "timestamp"):
            return self.timestamp
        else:
            return datetime.now()

    def get_source(self):
        if hasattr(self, "src"):
            return msb2lsb(str(self.src.hex()))
        else:
            return None
        
    def get_dest(self):
        if hasattr(self, "dest"):
            return msb2lsb(str(self.dest.hex()))
        else:
            return None
        
    def get_packet_id(self):
        if hasattr(self, "packet_id"):
            return msb2lsb(str(self.packet_id.hex()))
        else:
            return None
        
    def get_flags(self):
        if hasattr(self, "flags"):
            return str(self.flags.hex())
        else:
            return None
        
    def get_channel_hash(self):
        if hasattr(self, "channel_hash"):
            return str(self.channel_hash.hex())
        else:
            return None
        
    def get_reserved(self):
        if hasattr(self, "reserved"):
            return str(self.reserved.hex())
        else:
            return None
        
    def get_data(self):
        if hasattr(self, "data"):
            return str(self.data.hex())
        else:
            return None
        
    def get_message(self):
        if hasattr(self, "message"):
            return self.message
        else:
            return None

    def save(self):
        with open(f"{self.get_source()}-{self.get_dest()}-{self.timestamp.strftime("%Y%m%d-%H%M%S")}.txt", "wb") as f:
            f.write(self.raw)

    def decrypt(self, key):
        ## Try with PSK method
        try:
            aes_nonce = self.packet_id + b'\x00\x00\x00\x00' + self.src + b'\x00\x00\x00\x00'
            cipher = Cipher(algorithms.AES(b64_to_hex(key)), modes.CTR(aes_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            protobuf = decryptor.update(self.data) + decryptor.finalize()

            ## Try decode
            data = mesh_pb2.Data()
            data.ParseFromString(protobuf)
            self.message = Message(self.get_source(), self.get_dest(), data)

            return True
        except Exception as e:
            if not str(e).startswith("Error parsing message with type 'meshtastic.protobuf"):
                print(e)

        ## Try with PKI method
        try:
            ## TODO: Random nonce changes between source and dest, why? Eg. src: ffb7fd08, dest: ffb7cd08.
            ## NOTE: random is uint32le
            random = self.data[-4:]
            aes_nonce = self.packet_id + random + self.src + b'\x00\x00\x00\x00'

            ## TODO: need to derive shared secret from sender public key and recipient private key
            shared_secret = b64_to_hex(key)

            cipher = Cipher(algorithms.AES(shared_secret), modes.CTR(aes_nonce), backend=default_backend())
            decryptor = cipher.decryptor()
            protobuf = decryptor.update(self.data[:-4]) + decryptor.finalize()

            ## Try decode
            data = mesh_pb2.Data()
            data.ParseFromString(protobuf)
            self.message = Message(self.get_source(), self.get_dest(), data)

            return True
        except Exception as e:
            if not str(e).startswith("Error parsing message with type 'meshtastic.protobuf"):
                print(e)
        
        raise Exception("Unable to decrypt!")