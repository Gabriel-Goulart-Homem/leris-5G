#!/usr/bin/env python
import sys
import os
import json

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import BitField
from scapy.all import Ether, Dot1Q,IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

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

def handle_pkt(pkt):
   if (Ether in pkt and pkt[Ether].type == 0x8100) and TCP in pkt:
      print ("Pacote recebido de porta "+ str(pkt[TCP].sport) + " e vlan "+ str(pkt[Dot1Q].vlan))

def main(): 
    bind_layers(Ether, Dot1Q, type=0x8100)
    bind_layers(Dot1Q, MAC, type=0x8100)
    bind_layers(MAC,RLC)
    bind_layers(RLC, PDCP)
    bind_layers(PDCP,IP)
    bind_layers(IP, TCP)  

    print ("sniffing on eno7")
    sys.stdout.flush()
    sniff(iface = 'eno7',
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
