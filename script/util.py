import base64

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
