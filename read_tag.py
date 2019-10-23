from __future__ import print_function
import sys

import sys
sys.path.append('../scapy-cip-enip')

from cip import CIP, CIP_Path
import plc
from enip_tcp import ENIP_TCP, ENIP_SendUnitData, ENIP_SendUnitData_Item, \
    ENIP_ConnectionAddress, ENIP_ConnectionPacket, ENIP_RegisterSession, ENIP_SendRRData
import socket


def simple_read_tag(client, pathsize, classid, instanceid):
    # Symbol Instanc Addressing
    data = "\x01\x00"
    cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size = pathsize)) / data

    # Construct an enip packet from raw
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
    
    enippkt.show()

    # Show the response only if it does not contain data
    resppkt = client.recv_enippkt()
    if resppkt is not None:    
        print("Status: " + str(resppkt[CIP].status))
        # print(resppkt[CIP])



# CIP Path Size
def fuzz_pathsize(client, classid, instanceid):
    data = "\x01\x00"
    for pathsize in range(0xff):
        # Symbol Instanc Addressing
        cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size=pathsize)) / data
        
        try:
            client.send_unit_cip(cippkt)
        except:
            pass
  
        # Show the response only if it does not contain data
        resppkt = client.recv_enippkt()
        if resppkt is not None:    
            print("Status: " + str(resppkt[CIP].status))

# CIP class id
def fuzz_classid(client, instanceid):
    status = {}
    for classid in range(0x64, 0xc8):
        data = "\x01\x00"
        # Symbol Instanc Addressing
        cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size = 3)) / data

        print("class id: " + str(hex(classid)) + " | instance id: " + str(hex(instanceid)), end='\r')
        try:
            client.send_unit_cip(cippkt)
        except:
            pass
        # Show the response only if it does not contain data
        resppkt = client.recv_enippkt()
        if resppkt is not None:    
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
# CIP class id
def fuzz_service_classid(client, instanceid):
    status = {}
    for service in range(0xff):
        for classid in range(0xff):
            # Symbol Instanc Addressing
            cippkt = CIP(service=service, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size = 3))

            print("class id: " + str(hex(classid)) + " | service: " + str(hex(service)), end='\r')
            try:
                client.send_unit_cip(cippkt)
            except:
                pass
            # Show the response only if it does not contain data
            resppkt = client.recv_enippkt()
            if resppkt is not None:    
                stat = str(resppkt[CIP].status)
                if stat in status:
                    status.get(stat).append(str(hex(classid)) + str(hex(service)))
                else:
                    status[stat] = [str(hex(classid)) + str(hex(service))]
    # print all status
    for key, value in status.items():
        print("Status: " + key)
        for v in value:
            print("        " + v)


# CIP instance id
def fuzz_instanceid(client, classid):
    status = {}
    data = "\x01\x00"
    for instanceid in range(0xffff):
        # Symbol Instanc Addressing
        cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=classid, instance_id=instanceid, word_size=3)) / data

        # print("class id: " + str(hex(classid)) + " | instance id: " + str(hex(instanceid)), end='\r')
        try:
            client.send_unit_cip(cippkt)
        except:
            pass
        # Receive the response and show it
        resppkt = client.recv_enippkt()    
        # print("class id: " + str(hex(classid)) + " | instance id: " + str(hex(instanceid)) + " Status: " + str(resppkt[CIP].status))
        if resppkt is not None:    
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

# ENIP interface handle
def fuzz_interfacehandle(client):
    for i in range(0x1, 0xf):
        # i = 0x1
        print("Fuzzing interface handle: " + str(hex(i)))
        # Construct an enip packet from raw
        enippkt = ENIP_TCP(session=client.session_id)
        # Symbol Instanc Addressing
        cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=0xB2, instance_id=0x1f6, word_size=3))
        # interface handle, timeout, count, items
        enippkt /= ENIP_SendUnitData(interface_handle = i, items=[
            # type_id, length, connection id
            ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=client.enip_connid),
            # type_id, length, sequence
            ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=client.sequence) / cippkt
        ])
        client.sequence += 1
        if client.sock is not None:
            try:
                client.sock.send(str(enippkt))
            except:
                pass

        # Show the response only if it does not contain data
        resppkt = client.recv_enippkt()
        if resppkt is not None:    
            print("Status: " + str(resppkt[ENIP_TCP].status))
            print("Interface Handle: " + str(hex(resppkt[ENIP_SendUnitData].interface_handle)))

# ENIP timeout
def fuzz_timeout(client):
    for i in range(0xff):
        # i = 0x1
        print("Fuzzing timeout: " + str(hex(i)))
        # Construct an enip packet from raw
        enippkt = ENIP_TCP(session=client.session_id)
        # Symbol Instanc Addressing
        cippkt = CIP(service=0x4c, path=CIP_Path.make(class_id=0x6b, instance_id=0x227))
        # interface handle, timeout, count, items
        enippkt /= ENIP_SendUnitData(timeout = i, items=[
            # type_id, length, connection id
            ENIP_SendUnitData_Item() / ENIP_ConnectionAddress(connection_id=client.enip_connid),
            # type_id, length, sequence
            ENIP_SendUnitData_Item() / ENIP_ConnectionPacket(sequence=client.sequence) / cippkt
        ])
        client.sequence += 1
        if client.sock is not None:
            client.sock.send(str(enippkt))
        # Show the response only if it does not contain data
        resppkt = client.recv_enippkt()
        if resppkt is not None: 
            print("Status: " + str(resppkt[ENIP_TCP].status))
            print("TImeout: " + str(hex(resppkt[ENIP_SendUnitData].timeout)))



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
    # fuzz_instanceid(client, 0x6b)
    fuzz_classid(client, 0x1)
    # fuzz_service_classid(client, 0x0)
    # fuzz_pathsize(client, 0x6b, 0x227)
    # simple_read_tag(client, 3, 0x6b, 0x227)
    # Close the connection
    client.forward_close()

if __name__ == '__main__':
    main()
