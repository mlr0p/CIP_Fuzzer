from __future__ import print_function
import logging
import sys
sys.path.append('../scapy-cip-enip')
import time


from cip import CIP, CIP_Path
import plc
import scapy


logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

# Connect to PLC
client = plc.PLCClient('192.168.9.227')
if not client.connected:
    sys.exit(1)

# Creating Connections Through the Connection Manager Object 
if not client.forward_open():
    sys.exit(1)

string = "modified_recipe"
# Tag Type Service Parameter for Structures (\xa0\x02 + 4-byte structure handle) + Length (DINT - 4 bytes) + String (131 bytes, padded with null bytes)
tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
data = tag_type_service_param+ "\x0f\x00\x00\x00" + string + '\x00' * (132 - len(string))
cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=0x227)) / data
client.send_unit_cip(cippkt)
resppkt = client.recv_enippkt()   
resppkt.show()

# Close the connection
client.forward_close()