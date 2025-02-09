from util import hex_to_binary

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
