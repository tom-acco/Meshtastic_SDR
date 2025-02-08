import argparse
import base64
import json
import zmq
import time

from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from meshtastic import protocols, mesh_pb2, admin_pb2, portnums_pb2, telemetry_pb2, mqtt_pb2

parser = argparse.ArgumentParser(description = "Process incoming command parmeters")
parser.add_argument("ip", action = "store", help = "IP Address.")
parser.add_argument("port", action = "store", help = "Port")
parser.add_argument("-d", "--debug", action = "store_true", dest = "debug", help = "Print more debug messages")
args = parser.parse_args()

debug = False

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

        self.aes_nonce = self.packet_id + b'\x00\x00\x00\x00' + self.src + b'\x00\x00\x00\x00'

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

    def decrypt(self, key):
        try:
            ## Decrypt
            cipher = Cipher(algorithms.AES(b64_to_hex(key)), modes.CTR(self.aes_nonce), backend=default_backend())
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

            raise Exception(e)

class PacketData(object):
    def __init__(self, raw_data):
        self.raw = raw_data
        self.hex = self.raw.hex()

        # https://meshtastic.org/docs/overview/mesh-algo/
        # NOTE: The data coming out of GnuRadio is MSB or big endian. We have to reverse byte order after this step.

        # destination : 4 bytes 
        # sender      : 4 bytes
        # packetID    : 4 bytes
        # flags       : 1 byte
        # channelHash : 1 byte
        # reserved    : 2 bytes
        # data        : 0-237 bytes

        self.hex_data = {
            'dest' : self.hex[0:8],
            'src' : self.hex[8:16],
            'packet_id' : self.hex[16:24],
            'flags' : self.hex[24:26],
            'channel_hash' : self.hex[26:28],
            'reserved' : self.hex[28:32],
            'data' : self.hex[32:len(self.hex)]
        }

        try:
            self.dest = hex_to_binary(self.hex_data["dest"])
        except Exception as e:
            print(f"Error getting message destination: {e}")

        try:
            self.src = hex_to_binary(self.hex_data["src"])
        except Exception as e:
            print(f"Error getting message source: {e}")

        try:
            self.packet_id = hex_to_binary(self.hex_data["packet_id"])
        except Exception as e:
            print(f"Error getting message packet_id: {e}")

        try:
            self.flags = hex_to_binary(self.hex_data["flags"])
        except Exception as e:
            print(f"Error getting message flags: {e}")

        try:
            self.channel_hash = hex_to_binary(self.hex_data["channel_hash"])
        except Exception as e:
            print(f"Error getting message channel_hash: {e}")

        try:
            self.reserved = hex_to_binary(self.hex_data["reserved"])
        except Exception as e:
            print(f"Error getting message reserved: {e}")

        try:
            self.data = hex_to_binary(self.hex_data["data"])
        except Exception as e:
            print(f"Error getting message data: {e}")
    
    def get_dest(self):
        if hasattr(self, "dest"):
            return self.dest
        else:
            return None

    def get_source(self):
        if hasattr(self, "src"):
            return self.src
        else:
            return None
        
    def get_packet_id(self):
        if hasattr(self, "packet_id"):
            return self.packet_id
        else:
            return None
        
    def get_flags(self):
        if hasattr(self, "flags"):
            return self.flags
        else:
            return None
        
    def get_channel_hash(self):
        if hasattr(self, "channel_hash"):
            return self.channel_hash
        else:
            return None
        
    def get_reserved(self):
        if hasattr(self, "reserved"):
            return self.reserved
        else:
            return None
        
    def get_data(self):
        if hasattr(self, "data"):
            return self.data
        else:
            return None

class Message(object):
    def __init__(self, sourceId, destId, data):
        self.sourceId = sourceId
        self.destId = destId

        match data.portnum:
            case 0: # UNKNOWN_APP
                self.type = "UNKNOWN_APP"

            case 1: # TEXT_MESSAGE_APP
                self.type = "TEXT_MESSAGE_APP"
                self.data = data.payload.decode("utf-8")

            case 2 : # REMOTE_HARDWARE_APP
                self.type = "REMOTE_HARDWARE_APP"

            case 3 : # POSITION_APP
                self.type = "POSITION_APP"

                pos = mesh_pb2.Position()
                pos.ParseFromString(data.payload)

                self.data = {
                    "latitude": pos.latitude_i * 1e-7,
                    "longitude": pos.longitude_i * 1e-7
                }

            case 4 : # NODEINFO_APP
                self.type = "NODEINFO_APP"

                try:
                    info = mesh_pb2.User()
                    info.ParseFromString(data.payload)
                    self.data = str(info)
                except:
                    self.data = None

            case 5 : # ROUTING_APP
                self.type = "ROUTING_APP"

                routing = mesh_pb2.Routing()
                routing.ParseFromString(data.payload)
                self.data = str(routing)

            case 6 : # ADMIN_APP
                self.type = "ADMIN_APP"

                admin = admin_pb2.AdminMessage()
                admin.ParseFromString(data.payload)
                self.data = str(admin)

            case 7 : # TEXT_MESSAGE_COMPRESSED_APP
                self.type = "TEXT_MESSAGE_COMPRESSED_APP"

            case 10 : # DETECTION_SENSOR_APP
                self.type = "DETECTION_SENSOR_APP"

            case 32 : # REPLY_APP
                self.type = "REPLY_APP"

            case 33 : # IP_TUNNEL_APP
                self.type = "IP_TUNNEL_APP"

            case 34 : # PAXCOUNTER_APP
                self.type = "PAXCOUNTER_APP"

            case 64 : # SERIAL_APP
                self.type = "SERIAL_APP"

            case 65 : # STORE_FORWARD_APP
                self.type = "STORE_FORWARD_APP"

                sfwd = mesh_pb2.StoreAndForward()
                sfwd.ParseFromString(data.payload)
                self.data = str(sfwd)

            case 67 : # TELEMETRY_APP
                self.type = "TELEMETRY_APP"

                telemetry = telemetry_pb2.Telemetry()
                telemetry.ParseFromString(data.payload)
                self.data = str(telemetry)

            case 68 : # ZPS_APP
                self.type = "ZPS_APP"

                z_info = mesh_pb2.zps()
                z_info.ParseFromString(data.payload)
                self.data = str(z_info)

            case 69 : # SIMULATOR_APP
                self.type = "SIMULATOR_APP"

            case 70 : # TRACEROUTE_APP
                self.type = "TRACEROUTE_APP"

                trct = mesh_pb2.RouteDiscovery()
                trct.ParseFromString(data.payload)
                self.data = str(trct)

            case 71 : # NEIGHBORINFO_APP
                self.type = "NEIGHBORINFO_APP"

                ninfo = mesh_pb2.NeighborInfo()
                ninfo.ParseFromString(data.payload)
                self.data = str(ninfo)

            case 72 : # ATAK_PLUGIN
                self.type = "ATAK_PLUGIN"

            case 73 : # MAP_REPORT_APP
                self.type = "MAP_REPORT_APP"

                mrpt = mesh_pb2.MapReport()
                mrpt.ParseFromString(data.payload)
                self.data = str(mrpt)

            case 74 : # POWERSTRESS_APP
                self.type = "POWERSTRESS_APP"

            case 256 : # PRIVATE_APP
                self.type = "PRIVATE_APP"

            case 257 : # ATAK_FORWARDER
                self.type = "ATAK_FORWARDER"

            case _ : # UNKNOWN 
                self.type = "UNKNOWN"

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__)

def msb2lsb(msb):
    #string version of this. ONLY supports 32 bit from the sender/receiver ID. Hacky
    lsb = msb[6] + msb[7] + msb[4] + msb[5] + msb[2] + msb[3] + msb[0] + msb[1]
    return lsb

def hex_to_binary(hexString):
    binString = bytes.fromhex(hexString)
    return binString

def b64_to_hex(b64String):
    try:
        return base64.b64decode(b64String.encode('ascii'))
    except Exception as e:
        print(f"Failed to convert b64 to hex: {e}")

def validate_aes_key(key = None):
    if not key:
        return False

    if debug:
        print(f"[DEBUG] Validating key: {key}")

    try:
        key_len = len(base64.b64decode(key).hex())

        if key_len == 2:
            key = f"1PG7OiApB1nwvP+rz05p{key}"
            key_len = len(base64.b64decode(key).hex())

            if debug:
                print(f"[DEBUG] Added Meshtastic static key to 2 bit key: {key}")

        if debug:
            print(f"[DEBUG] key_len: {key_len}")

        if (key_len == 32 or key_len == 64):
            pass
        else:
            return False

        if debug:
            print(f"[DEBUG] Key valid")
            print("-"*50)

        return key
    except Exception as e:
        return False

def handle_packet(pkt = None):
    packet = Packet(pkt)

    print(f"[INFO] Received packet! @ {packet.get_timestamp()}")
    
    if debug:
        print("-" * 50)
        print(f"[DEBUG] Src: {packet.get_source()}")
        print(f"[DEBUG] Dest: {packet.get_dest()}")
        print(f"[DEBUG] PacketId: {packet.get_packet_id()}")
        print(f"[DEBUG] Flags: {packet.get_flags()}")
        print(f"[DEBUG] ChannelHash: {packet.get_channel_hash()}")
        print(f"[DEBUG] Data: {packet.get_data()}")
        print("-" * 50)
    
    decrypted = False

    print(f"[INFO] Attempting to decrypt...")
    for key in keys:
        try:
            decrypted = packet.decrypt(key)
            break
        except Exception as e:
            continue
    
    if decrypted:
        print(f"[INFO] Success!")
        message = packet.get_message()

        print(message.to_json())
    else:
        print("[INFO] Failed :(")

    print("-" * 50)

def listen_on_network(ip = None, port = None, keys = []):
    if not ip or not port:
        raise Exception("Missing IP or Port!")

    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    socket.connect("tcp://" + ip + ":" + port)
    socket.setsockopt(zmq.SUBSCRIBE, b'')

    while True:
        if socket.poll(10) != 0:
            pkt = socket.recv()
            handle_packet(pkt)
        else:
            time.sleep(0.1)

if __name__ == "__main__":
    if args.debug:
        debug = True

    try:
        with open("keys", "r") as file:
            temp_keys = [line.strip() for line in file]
    except Exception as e:
        temp_keys = ["1PG7OiApB1nwvP+rz05pAQ=="]

    keys = []

    for key in temp_keys:
        if not key or key.startswith("#"):
            continue

        valid_key = validate_aes_key(key)

        if not valid_key:
            print(f"[WARN] Key '{key}' is not a valid AES 128/256 key!")
        else:
            keys.append(valid_key)

    if len(keys) > 0:
        print(f"[INFO] Loaded {len(keys)} keys")
    else:
        print(f"[WARN] No keys loaded.")

    listen_on_network(args.ip, args.port, keys)

