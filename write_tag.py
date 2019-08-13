from __future__ import print_function
import logging
import sys
sys.path.append('../scapy-cip-enip')
import time

from cip import CIP, CIP_Path
import plc
import scapy
import struct
import random

TAG_TYPE = {
    "BOOL":0x00c1,  # 1 byte 0x0nc1
    "SINT":0x00c2,  # 1 byte
    "INT":0x00c3,   # 2 bytes
    "DINT":0x00c4,  # 4 bytes
    "REAL":0x00ca,  # 4 bytes
    "DWORD":0x00d3, # 4 bytes
    "LINT":0x00c5   # 8 bytes
}


logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

def write_tag_string(client, instanceid, string):
    # Tag Type Service Parameter for Structures (\xa0\x02 + 4-byte structure handle) + Length (DINT - 4 bytes) + String (131 bytes, padded with null bytes)
    tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
    data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
    cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid)) / data
    client.send_unit_cip(cippkt)
    resppkt = client.recv_enippkt()
    print(resppkt[CIP].status)

def write_tag_float(client, instanceid, val):
    # Tag Type Value (0xc400) + Number of elements to write (0x100) + Data (4 bytes)
    data = "\xca\x00" + "\x01\x00" + struct.pack("<f", val)
    cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid)) / data
    client.send_unit_cip(cippkt)
    resppkt = client.recv_enippkt()
    print(resppkt[CIP].status)

def fuzz_write_float(client):
    start = time.time()
    # ROUND = 2000
    cur_round = 0
    # print column
    print("Path Size\tClass ID\tInstance ID\tTag Data Type\tElement Count\tData\t\tStatus")
    # cip.py is modified to take word size as field param
    for wordsize in [2, 3, 4]:
        for classid in xrange(0x100):
            for instanceid in xrange(0x10000):
                for tagtype in TAG_TYPE.values():
                    for num in [0, 1, 2]:
                        for float_data in xrange(0x10):          
                            float_data = random.randint(0, 0x100000000)     
                            data = struct.pack("I", tagtype) + struct.pack("I", num) + struct.pack("<f", float_data)
                            cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size=wordsize)) / data
                            client.send_unit_cip(cippkt)
                            resppkt = client.recv_enippkt()
                            # Log Data
                            print("%d\t\t0x%x\t\t0x%x\t\t0x%x\t\t%d\t\t0x%x\t%s" % (wordsize, classid, instanceid, tagtype, num, float_data, str(resppkt[CIP].status)))
                            if (cur_round % 100 == 0):
                                elapsed_time = time.time() - start
                                sys.stderr.write("Round: %d | Time: %d sec\r" % (cur_round, elapsed_time))
                            cur_round+=1




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

# Fuzz with naughty strings
def fuzz_string(client, classid, instanceid):
    # Tag Type Service Parameter for Structures (\xa0\x02 + 4-byte structure handle) + Length (DINT - 4 bytes) + String (131 bytes, padded with null bytes)
    tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
    
    # https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/big-list-of-naughty-strings.txt
    with open("big-list-of-naughty-strings.txt") as f:
        content = f.readlines()
    
    linenum = 0
    for string in content:
        linenum+=1
        print("current string: " + string)
        print("string length: " + str(len(string)))
        print("current line number: " + str(linenum))
        if len(string) < 132:
            data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\xcc' * (132 - len(string))
        else:
            data = tag_type_service_param+ struct.pack('<I',len(string)) + string
        cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid)) / data
        client.send_unit_cip(cippkt)
        # resppkt = client.recv_enippkt()
        # print(resppkt[CIP].status)
        time.sleep(1)


def main():
    # Connect to PLC
    client = plc.PLCClient('192.168.9.227')
    if not client.connected:
        sys.exit(1)

    # Creating Connections Through the Connection Manager Object 
    if not client.forward_open():
        sys.exit(1)
    # string = sys.argv[1]
    # fuzz_instanceid(client, 0x6b, string)
    # fuzz_string(client, 0x6b, 0x227)
    # write_tag_string(client, string, 0x227)
    # write_tag_float(client, 0x1e3, 1337.0)
    fuzz_write_float(client)


    # Close the connection
    client.forward_close()

if __name__ == '__main__':
    main()