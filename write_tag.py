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
    # Tag Type Service Parameter for Structures (\xa0\x02 + 4-byte structure handle) + Length (DINT - 4 bytes) + String (131 bytes, padded with null bytes)
    tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
    data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
    cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=0x227)) / data
    client.send_unit_cip(cippkt)
    resppkt = client.recv_enippkt()
    print(resppkt[CIP].status)

def fuzz_instanceid(client, classid, string):
    # record te status
    status = {}
    for instanceid in range(0xffff):
        # Construct packets
        tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
        data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
        cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid)) / data

        print("class id: " + str(hex(classid)) + " | instance id: " + str(hex(instanceid)))
        try:
            client.send_unit_cip(cippkt)
        except:
            pass
        # Receive the response and show it
        resppkt = client.recv_enippkt() 
        stat = str(resppkt[CIP].status)
        if stat in status:
            status.get(stat).append(str(hex(instanceid)))
        else:
            status[stat] = [str(hex(instanceid))] 
    # print all status
    for key, value in status.items():
        print("Status: " + key)
        for v in value:
            print("        " + v)
def main():
    # Connect to PLC
    client = plc.PLCClient('192.168.9.227')
    if not client.connected:
        sys.exit(1)

    # Creating Connections Through the Connection Manager Object 
    if not client.forward_open():
        sys.exit(1)
    string = sys.argv[1]
    fuzz_instanceid(client, 0x6b, string)
    # simple_write_tag(client, string)
    # Close the connection
    client.forward_close()

if __name__ == '__main__':
    main()