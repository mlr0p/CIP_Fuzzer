from __future__ import print_function
import sys
sys.path.append('../scapy-cip-enip')
import time

from cip import CIP, CIP_Path
import plc
import scapy
import struct

class Tag:
    def __init__(self, instance_id, symbol_name, symbol_type):
        """ constructor, called when a tag is created, properties include: 
            instance_id: 32-bit
            symbol_name: variable length string
            symbol_type: 16-bit
            tag_type: structured / atomic
            system_tag: boolean
            tag_dimension: 0 ~ 3 dimension
        """
        # 32-bit
        self.instance_id = instance_id
        # variable length
        self.symbol_name = symbol_name
        # 16-bit
        self.symbol_type = symbol_type
        # decodes the symbol_type value
        symbol_type_binary = format(symbol_type, '016b')
        # bit 15 determines atomic or structured tag
        if(symbol_type_binary[15] == '1'):
            self.tag_type = "structured"
        else:
            self.tag_type = "atomic"        
        # bit 12 deter,omes of the tag is a system tag (reserved)
        if(symbol_type_binary[12] == '1'):
            self.system_tag = True
        else:
            self.system_tag = False
        # bits 13 and 14 indicates the dimensions of the tag
        self.tag_dimension = int(symbol_type_binary[13:15], 2)
        # bits from 0 to 11 is the Tag Type Service Parameter
        self.tag_type_instanceid = symbol_type ^ 0xfff

# Store all the tags
tags = []


def parse_attributes(raw_data):
    """ Parse the response from the Get_Instance_Attribute_List """
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
        # Get 2-byte Symbol Name Length
        data = raw_data[curptr:curptr+2]   
        curptr += 2
        symbol_len = struct.unpack('<H', data)[0]
        # Read the symbol name
        symbol_name = raw_data[curptr:curptr+symbol_len]   
        curptr += symbol_len
        # Get 2-byte Symbol Type
        data = raw_data[curptr:curptr+2]   
        curptr += 2
        symbol_type = struct.unpack('<H', data)[0]
        # Construct a tag and put in the global list
        tags.append(Tag(instance_id, symbol_name, symbol_type))
    return last_instance_id

def main():
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
        instanceid = parse_attributes(resppkt[CIP].load) + 1

    client.forward_close()

def show_tags():
    for tag in tags:
        print("instance id: " + str(hex(tag.instance_id)))
        print("symbol name: " + tag.symbol_name)
        print("symbol type: " + str(hex(tag.symbol_type)))
        print("tag type: " + tag.tag_type)
        print("system tag: " + str(tag.system_tag))
        print("tag dimension: " + str(tag.tag_dimension))
        print("tag type instance id: " + str(hex(tag.tag_type_instanceid)))
        print("================================")


if __name__ == "__main__":
    main()
    show_tags()