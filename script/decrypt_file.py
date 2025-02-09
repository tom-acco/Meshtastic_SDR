import argparse
import base64

from packet import Packet

parser = argparse.ArgumentParser(description = "Decrypt saved files")
parser.add_argument("file", action = "store", help = "The file to decrypt.")
parser.add_argument("key", action = "store", help = "The key to use")
parser.add_argument("-d", "--debug", action = "store_true", dest = "debug", help = "Print more debug messages")
args = parser.parse_args()

debug = False

def decrypt(file = None, key = None):
    try:
        with open(args.file, "rb") as f:
            raw_data = f.read()
    except Exception as e:
        print(f"Failed to open file: {e}")
        return False

    packet = Packet(raw_data)

    if debug:
        print("-" * 50)
        print(f"[DEBUG] Src: {packet.get_source()}")
        print(f"[DEBUG] Dest: {packet.get_dest()}")
        print(f"[DEBUG] PacketId: {packet.get_packet_id()}")
        print(f"[DEBUG] Flags: {packet.get_flags()}")
        print(f"[DEBUG] ChannelHash: {packet.get_channel_hash()}")
        print(f"[DEBUG] Data: {packet.get_data()}")
        print("-" * 50)

    try:
        packet.decrypt(key)
        message = packet.get_message()
        print(message.to_json())
    except Exception as e:
        print(f"Error decrypting: {e}")

if __name__ == "__main__":
    if args.debug:
        debug = True

    key_len = len(base64.b64decode(args.key).hex())

    if key_len == 2:
        args.key = f"1PG7OiApB1nwvP+rz05p{args.key}"

    decrypt(args.file, args.key)