from __future__ import print_function
import sys
sys.path.append('../scapy-cip-enip')
import time

from cip import CIP, CIP_Path
import plc
import scapy
import struct

# Parse the response from the Get_Instance_Attribute_List
def parse_attributes(raw_data):
    # Returns the last instance id
    last_instance_id = 0
    # pointer
    curptr = 0
    while(curptr != len(raw_data)):
        # Get 4-byte Instance ID
        data = raw_data[curptr:curptr+4]   
        curptr += 4
        # We've reached the end if no more data to read
        if(curptr >= len(raw_data)):
            break
        instance_id = struct.unpack('<I', data)[0]
        last_instance_id = instance_id
        print("Instance ID: " + str(hex(instance_id)))
        # Get 2-byte Symbol Name Length
        data = raw_data[curptr:curptr+2]   
        curptr += 2
        symbol_len = struct.unpack('<H', data)[0]
        print("Symbol Length: " + str(hex(symbol_len)))
        # Read the symbol name
        data = raw_data[curptr:curptr+symbol_len]   
        curptr += symbol_len
        print("Symbol Name: " + str(data))
        # Get 2-byte Symbol Type
        data = raw_data[curptr:curptr+2]   
        curptr += 2
        symbol_type = struct.unpack('<H', data)[0]
        print("Symbol Type: " + str(hex(symbol_type)))
        print("===========================================")
    return last_instance_id


# Connect to PLC
client = plc.PLCClient('192.168.9.227')
if not client.connected:
    sys.exit(1)

# Creating Connections Through the Connection Manager Object 
if not client.forward_open():
    sys.exit(1)

# Get_Instance_Attribute_List
# Set initial instance to 0x0
instanceid = 0x0
# status
status = ''
# Number of attributes to retrieve (2 bytes) + Attribute 1 - Symbol Name (2 bytes) + Attribute 2 - Symbol Type (2 bytes)
data = "\x02\x00\x01\x00\x02\x00"

while("Success" not in status):
    cippkt = CIP(service=0x55, path=CIP_Path.make(class_id=0x6b, instance_id=instanceid)) / data
    client.send_unit_cip(cippkt)
    resppkt = client.recv_enippkt() 
    status = str(resppkt[CIP].status)
    print("Parsing Attribute Response: \n===========================================")
    instanceid = parse_attributes(resppkt[CIP].load)

client.forward_close()