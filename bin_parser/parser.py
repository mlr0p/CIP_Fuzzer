import struct


# Parse the binary data from the PLC into a more readable format
print("[+] Parsing 0x1e0.bin...")
with open("0x1f6.bin", "rb") as f:
  index = 1
  data = f.read(2)
  while data != b"":
    i = struct.unpack('<H', data)[0]
    if(i == index):
      index+=1
      print("index " + str(i), end=": ")
      # Read everything until the next index
      if(i==0x36):
        data = f.read(131)
        print(data)
      else:
        data = f.read(4)
        print(struct.unpack('<f', data)[0])
    # Read the next index
    data = f.read(2)




# Parse the binary data from the PLC into a more readable format
print()
print("[+] Parsing 0x1e1.bin...")
with open("0x1f7.bin", "rb") as f:
  index = 1
  data = f.read(2)
  while data != b"":
    i = struct.unpack('<H', data)[0]
    if(i == index):
      index+=1
      print("index " + str(i), end=": ")
      # Read everything until the next index
      if(i==0x01):
        data = f.read(136)
        print(data)
      else:
        data = f.read(4)
        print(struct.unpack('<f', data)[0])
    # Read the next index
    data = f.read(2)
