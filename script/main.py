import argparse
import base64
import json
import zmq
import time

from packet import Packet

parser = argparse.ArgumentParser(description = "Process incoming command parmeters")
parser.add_argument("ip", action = "store", help = "IP Address.")
parser.add_argument("port", action = "store", help = "Port")
parser.add_argument("-d", "--debug", action = "store_true", dest = "debug", help = "Print more debug messages")
parser.add_argument("-s", "--save", action = "store_true", dest = "save", help = "Save packets to disk")
args = parser.parse_args()

debug = False
save = False

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

    print("-" * 20, " PACKET ", "-" * 20)
    print(f"[INFO] Received @ {packet.get_timestamp()}")

    if save:
        print(f"[INFO] Saving...")
        packet.save()
    
    if debug:
        print(f"[DEBUG] Src: {packet.get_source()}")
        print(f"[DEBUG] Dest: {packet.get_dest()}")
        print(f"[DEBUG] PacketId: {packet.get_packet_id()}")
        print(f"[DEBUG] Flags: {packet.get_flags()}")
        print(f"[DEBUG] ChannelHash: {packet.get_channel_hash()}")
        print(f"[DEBUG] Data: {packet.get_data()}")
    
    decrypted = False

    print(f"[INFO] Attempting to decrypt...")
    for key in keys:
        try:
            decrypted = packet.decrypt(key)
            break
        except Exception as e:
            continue
    
    if decrypted:
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

    if args.save:
        save = True

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

