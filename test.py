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

# Get_Instance_Attribute_List
# Set initial instance to 0x0
instanceid = 0x0

data = "\x02\x00\x01\x00\x02\x00"
cippkt = CIP(service=0x55, path=CIP_Path.make(class_id=0x6b, instance_id=instanceid)) / data
client.send_unit_cip(cippkt)
resppkt = client.recv_enippkt() 
resppkt[CIP].show()

client.forward_close()