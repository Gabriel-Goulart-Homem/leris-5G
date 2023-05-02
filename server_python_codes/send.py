#!/usr/bin/env python
import keyboard
import sys
import socket
import os
import threading
import time
import struct

from scapy.all import sendpfast, sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, Dot1Q, IP, UDP, TCP, Raw
from scapy.all import BitField

class MAC(Packet):
    name = "MAC"
    fields_desc = [ 
    	BitField("R1",0,size=1), 
    	BitField("R2",0,size=1), 
    	BitField("LCID",0,size=6),
    	BitField("eLCID",0,size=8)
    	]

class RLC(Packet):
    name = "RLC"
    fields_desc = [ 
    	BitField("D_C",0,1), 
    	BitField("P",0,1), 
    	BitField("SI",0,2),
    	BitField("R1",0,1),
    	BitField("R2",0,1),
    	BitField("SN1",0,2),
    	BitField("SN2",0,8),
    	BitField("SN3",0,8),
    	BitField("SO1",0,8),
    	BitField("SO2",0,8),
    	]

class PDCP(Packet):
    name = "PDCP"
    fields_desc = [ 
    	BitField("R1",0,1), 
    	BitField("R2",0,1),
    	BitField("R3",0,1), 
    	BitField("R4",0,1), 
    	BitField("PDCP_SN1",0,4),
    	BitField("PDCP_SN2",0,8),
    	]

class Timestamp(Packet):
    name = "Timestamp"
    fields_desc = [
        BitField("Time",0,64)
            ]

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eno1"
    for i in get_if_list():
        if "eno7" in i:
            iface=i
            break;
    if not iface:
        print ("Cannot find eno1 interface")
        exit(1)
    return iface

def floatToBits(t):
    s = struct.pack('>f',t)
    return struct.unpack('>l',s)[0]

def main():

    if len(sys.argv)<3:
        print ('pass 2 arguments: <destination> <num_vlan1> <num_vlan2>')
        exit(1)

    bind_layers(Ether, Dot1Q,type=0x8100)
    bind_layers(Dot1Q, MAC,type=0x8100)
    bind_layers(MAC,RLC)
    bind_layers(RLC, PDCP)
    bind_layers(PDCP,IP)
    bind_layers(IP, TCP)

    for i in range(int(sys.argv[2])):
        x = threading.Thread(target=Sender, args=(50000+i, 1,))
        x.start()
        print("Criada thread numero: "+str(i)+ " da vlan 1")
    print("\n")
    for i in range(int(sys.argv[3])):
        x = threading.Thread(target=Sender, args=(51000+i, 2,))
        x.start()
        print("Criada thread numero: "+str(i)+ " da vlan 2")
    #Sender(50000,1)
    monitorKey()

def monitorKey():
    while True:
        try:
            if keyboard.read_key() == 'q':
                print("You pressed q")
                os._exit(0)
        except:
            os._exit(0)

def Sender(port, vlan):   
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("Mandando pacotes na porta "+ str(port)+ " e vlan "+ str(vlan))
    #print ("sending on interface %s to %s" % (iface, str(addr))) 
    pkt = Ether(src=get_if_hwaddr(iface), dst="ac:1f:6b:67:06:40",type=0x8100) / Dot1Q(vlan=vlan,type=0x8100)
    pkt = pkt / MAC()
    pkt = pkt / RLC()
    pkt = pkt / PDCP()
    pkt = pkt / IP(dst=addr, proto=6) / TCP(dport=port, sport=port) / Raw("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    #pkt.show2()
    print("Iniciado sport: "+str(port))
    temp = sendpfast(pkt, iface=iface, pps=1000, loop=10000, parse_results=True, file_cache = 0)
    print("Finalizado sport: "+str(port))

if __name__ == '__main__':
    main()
