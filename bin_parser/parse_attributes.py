import struct


# Parse the binary data from the PLC into a more readable format
print("[+] Parsing ...")


with open("0x0.bin", "rb") as f:
    data = None
    while data != b"":
        # Get 4-byte Instance ID
        data = f.read(4)
        # We've reached the end if no more data to read
        if(data == b""):
            break
        print(data)
        instance_id = struct.unpack('<I', data)[0]
        print("Instance ID: " + str(hex(instance_id)))
        # Get 2-byte Symbol Name Length
        data = f.read(2)
        symbol_len = struct.unpack('<H', data)[0]
        print("Symbol Length: " + str(hex(symbol_len)))
        # Read the symbol name
        data = f.read(symbol_len)
        print("Symbol Name: " + str(data))
        # Get 2-byte Symbol Type
        data = f.read(2)
        symbol_type = struct.unpack('<H', data)[0]
        print("Symbol Type: " + str(hex(symbol_type)))
        print("===========================================")
