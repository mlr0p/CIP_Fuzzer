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

from enip_tcp import ENIP_TCP, ENIP_SendUnitData, ENIP_SendUnitData_Item, \
    ENIP_ConnectionAddress, ENIP_ConnectionPacket, ENIP_RegisterSession, ENIP_SendRRData
import socket

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
    string = "\xCC"*130
    # Tag Type Service Parameter for Structures (\xa0\x02 + 2-byte structure handle) + Length (DINT - 2 bytes) + String (131 bytes, padded with null bytes)
    tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
    # tag_type_service_param = "\xde\xad\xbe\xef\xAA\xAA"
    data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
    cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid, word_size = 1)) / data
    enippkt = ENIP_TCP(session=client.session_id)
    # interface handle, timeout, count, items
    enippkt /= ENIP_SendUnitData(interface_handle = 0x0, items=[
        # type_id, length, connection id
        ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=client.enip_connid),
        # type_id, length, sequence
        ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=client.sequence) / cippkt
    ])
    client.sequence += 1
    if client.sock is not None:
        client.sock.send(str(enippkt))
    
    # client.send_unit_cip(cippkt)
    resppkt = client.recv_enippkt()
    resppkt[CIP].show()

def write_tag_float(client, instanceid, val):
    # Tag Type Value (0xc400) + Number of elements to write (0x100) + Data (4 bytes)
    data = "\xca\x00" + "\x01\x00" + struct.pack("<f", val)
    cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid, word_size = 3)) / data
    cippkt.show()
    client.send_unit_cip(cippkt)
    resppkt = client.recv_enippkt()
    print(resppkt[CIP].status)

def fuzz_write_float(client):
    start = time.time()
    cur_round = 0
    # print column
    print("Size\tClass ID\tInstance ID\tTag Data Type\tElement Count\tData\t\tStatus")
    # classid = 0x6b
    wordsize = 3
    num = 1
    status = {}
    # cip.py is modified to take word size as field param
    for classid in xrange(0x64, 0xc8):
        for instanceid in xrange(0x10000):
            for tagtype in xrange(0x10000):        
                # float_data = random.randint(0, 0x100000000) 
                float_data = 1337.0 
                data = struct.pack("h", tagtype) + struct.pack("h", num) + struct.pack("<f", float_data)
                # instanceid = random.randint(0, 0xffff)   
                cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size=wordsize)) / data
                client.send_unit_cip(cippkt)
                # cippkt.show()
                resppkt = client.recv_enippkt()
                # check if we have received it
                if resppkt is not None: 
                    stat = str(resppkt[CIP].status)
                    # Add to status dictionary
                    if stat in status:
                        status.get(stat).append(str(hex(classid)) + ": " +str(hex(instanceid)))
                    else:
                        status[stat] = [str(hex(classid)) + ": " +str(hex(instanceid))] 
                    # resppkt[CIP].show()
                    # Log Data
                    print("%d\t\t0x%x\t\t0x%x\t\t0x%x\t\t%d\t\t%f\t%s" % (wordsize, classid, instanceid, tagtype, num, float_data, str(stat)))
                    cur_round+=1
                    if (cur_round % 100 == 0):
                        elapsed_time = time.time() - start
                        sys.stderr.write("Round: %d | Time: %d sec\r" % (cur_round, elapsed_time))
    # print all status
    for key, value in status.items():
        sys.stderr.write("Status: " + key + "\n")
        for v in value:
            sys.stderr.write("        " + v + "\n")
    elapsed_time = time.time() - start
    sys.stderr.write("Total Elapsed Time: %d sec" % (elapsed_time))


def fuzz_pathsize(client, classid, instanceid, string):
    # record te status
    status = {}
    for wordsize in range(0xff):
        # Construct packets
        tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
        data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
        cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size=wordsize)) / data

        # print("class id: " + str(hex(classid)) + " | instance id: " + str(hex(instanceid)), end='\r')
        try:
            client.send_unit_cip(cippkt)
        except:
            pass
        # Receive the response and show it
        resppkt = client.recv_enippkt() 
        stat = str(resppkt[CIP].status)
        if stat in status:
            status.get(stat).append(str(hex(wordsize)))
        else:
            status[stat] = [str(hex(wordsize))] 
    # print all status
    for key, value in status.items():
        print("Status: " + key)
        for v in value:
            print("        " + v)


def fuzz_classid(client, instanceid, string):
    # record te status
    status = {}
    for classid in range(0xff):
        # Construct packets
        tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
        data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
        cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size=3)) / data

        # print("class id: " + str(hex(classid)) + " | instance id: " + str(hex(instanceid)), end='\r')
        try:
            client.send_unit_cip(cippkt)
        except:
            pass
        # Receive the response and show it
        resppkt = client.recv_enippkt() 
        stat = str(resppkt[CIP].status)
        if stat in status:
            status.get(stat).append(str(hex(classid)))
        else:
            status[stat] = [str(hex(classid))] 
    # print all status
    for key, value in status.items():
        print("Status: " + key)
        for v in value:
            print("        " + v)

def fuzz_instanceid(client, classid, string):
    # record te status
    status = {}
    for instanceid in range(0xffff):
        # Construct packets
        tag_type_service_param = "\xa0\x02\xbc\x2c\x01\x00"
        data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
        cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid, word_size=3)) / data

        # print("class id: " + str(hex(classid)) + " | instance id: " + str(hex(instanceid)), end='\r')
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
    with open("blns.txt") as f:
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
        cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid, word_size=3)) / data
        client.send_unit_cip(cippkt)
        # resppkt = client.recv_enippkt()
        # print(resppkt[CIP].status)
        # time.sleep(1)

def fuzz_recipe(client):
    recipe_instanceid = [0x16b, 0x18f, 0x198, 0x19b, 0x1a0, 0x1c5, 0x1cd, 0x1ce, 0x1cf]

    for round in xrange(0x10000):
        for instanceid in recipe_instanceid:
            val = random.randint(0, 0x100000000) 
            # Tag Type Value (0xc400) + Number of elements to write (0x100) + Data (4 bytes)
            data = "\xca\x00" + "\x01\x00" + struct.pack("I", val)

            cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=instanceid, word_size = 3)) / data
            cippkt.show()
            client.send_unit_cip(cippkt)
            resppkt = client.recv_enippkt()
            print(resppkt[CIP].status)
        if round %100 == 0:
            fuzz_string(client, 0x6b, 0x227)

def fuzz_string_tag_type_service_param(client, string):
    status = {}
    data = "\x01\x00"
    # Tag Type Service Parameter for Structures (\xa0\x02 + 2-byte structure handle) + Length (DINT - 2 bytes) + String (131 bytes, padded with null bytes)
    for structure_handle in xrange(0xffff):
        num = 0x1
        tag_type_service_param = "\xa0\x01" + struct.pack(">H", structure_handle) + struct.pack("H", num)
        data = tag_type_service_param+ struct.pack('<I',len(string)) + string + '\x00' * (132 - len(string))
        cippkt = CIP(service=0x4d, path=CIP_Path.make(class_id=0x6B, instance_id=0x227, word_size = 3)) / data
        enippkt = ENIP_TCP(session=client.session_id)
        # interface handle, timeout, count, items
        enippkt /= ENIP_SendUnitData(interface_handle = 0x0, items=[
            # type_id, length, connection id
            ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=client.enip_connid),
            # type_id, length, sequence
            ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=client.sequence) / cippkt
        ])
        client.sequence += 1
        if client.sock is not None:
            client.sock.send(str(enippkt))

        # client.send_unit_cip(cippkt)
        resppkt = client.recv_enippkt()
        if resppkt is not None:    
            stat = str(resppkt[CIP].status)
            if stat in status:
                status.get(stat).append(str(hex(structure_handle)))
            else:
                status[stat] = [str(hex(structure_handle))]
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
    # fuzz_string_tag_type_service_param(client, "test")
    # string = sys.argv[1]
    # fuzz_instanceid(client, 0x6b, 'test')
    # fuzz_classid(client, 0x1, 'test')
    # fuzz_string(client, 0x6b, 0x227)
    # string = 'not_string'
    # write_tag_string(client,0x227, 'test')
    # write_tag_float(client, 0x1e3, 1337.0)
    fuzz_write_float(client)
    # fuzz_recipe(client)
    # fuzz_pathsize(client, 0x6b, 0x227, 'test')



    # Close the connection
    client.forward_close()

if __name__ == '__main__':
    main()