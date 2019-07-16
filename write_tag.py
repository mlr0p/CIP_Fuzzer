from __future__ import print_function
import logging
import sys
sys.path.append('../scapy-cip-enip')
import time

from cip import CIP, CIP_Path
import plc
import scapy
import struct

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

def simple_write_tag(client, string):
    string = sys.argv[1]
    # Tag Type Service Parameter for Structures (\xa0\x02 + 4-byte structure handle) + Length (DINT - 4 bytes) + String (131 bytes, padded with null bytes)
    tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
    data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
    cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=0x227)) / data
    client.send_unit_cip(cippkt)
    resppkt = client.recv_enippkt()
    print(resppkt[CIP].status)

def main():
    # Connect to PLC
    client = plc.PLCClient('192.168.9.227')
    if not client.connected:
        sys.exit(1)

    # Creating Connections Through the Connection Manager Object 
    if not client.forward_open():
        sys.exit(1)

    # Fuzz the interface handle
    # fuzz_interfacehandle(client)
    # fuzz_timeout(client)
    # fuzz_instanceid(client, 0xB2)
    # fuzz_classid(client, 0x1f6)
    # fuzz_pathsize(client, 0xB2, 0x1f6)
    simple_write_tag(client, sys.argv[1])
    # Close the connection
    client.forward_close()

if __name__ == '__main__':
    main()