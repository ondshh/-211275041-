#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
class unarp_ipv4:
    def __init__(self,packet,intf,dstip):
        self.packet = packet
        self.send_count = 0
        self.send_time = 0.01
        self.intf = intf
        self.dstip = dstip
    
wait_reply = []
table={}
arp_table = {}

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        all_intf = self.net.interfaces()
        for intf in all_intf:
            mask = intf.netmask
            prefix = IPv4Address(int(intf.ipaddr)&int(mask))
            network = IPv4Network(str(prefix) + '/' + str(mask))
            table[network] = ['',intf.name] 
        f = open('forwarding_table.txt','r')
        all_line = f.readlines()
        for line in all_line:
            ifmt = line.rsplit()
            strx = IPv4Network(ifmt[0] + '/' + ifmt[1])
            table[strx] = ifmt[2:]
        print(table)
        print('============================================')


        # other initialization stuff here

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        all_intf = self.net.interfaces()
        ipvfour = packet.get_header(IPv4)
        arp = packet.get_header(Arp)
        if arp:#judge
            arp_table[arp.senderprotoaddr] = arp.senderhwaddr
            print("we get a ARp pkt")
            print(arp_table)
            if arp.operation == ArpOperation.Request:
                for intf in all_intf:
                    if arp.targetprotoaddr == intf.ipaddr:
                        print("Has a intf == arp tdst ip") 
                        packet = create_ip_arp_reply(intf.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                        self.net.send_packet(intf.name,packet)
                        log_info (f"Send packet {packet} to {intf.name}")
        elif ipvfour:
            print(" Get a ipvfour packet !!!!")
            judge = True
            for intf in all_intf:
                if ipvfour.dst == intf.ipaddr:
                    judge = False
                    break
            if judge:
                print("There is no intf is the ipv4 dstip")
                dst_ip = ipvfour.dst
                match = '0.0.0.0/0'
                aganst = -1
                for key in table.keys():#find the longest prefix
                    if dst_ip in key:
                        if aganst < key.prefixlen:
                            aganst = key.prefixlen
                            match = key
                if aganst != -1:
                    print("We have find a match !\n")
                    if table[match][0]:
                        destination = table[match][0]
                    else:
                        destination = packet[1].dst
                    if ipvfour.dst in arp_table.keys():
                        for intf in all_intf:
                            if table[match][1] == intf.name:
                                packet[0].src = intf.ethaddr
                                break
                        packet[1].ttl -= 1
                        packet[0].dst = arp_table[ipvfour.dst]
                        self.net.send_packet(table[match][1],packet)
                        log_info (f"Send packet {packet} to {intf.name}")
                    else:
                        ipvfour.ttl -= 1
                        print("we get 1")
                        pkt = unarp_ipv4(packet,table[match][1],destination)
                        print("we get 2")
                        wait_reply.append(pkt)
        print(wait_reply)
        cwait = wait_reply
        for wpkt in cwait:
            print(" =======we get in wpkt======")
            for ip in arp_table.keys():
                print("Now checking in arp_table")
                print(arp_table)
                if wpkt.dstip == ip:
                    print("find a ip == wpkt.dstip")
                    for intf in all_intf:
                        if intf.name == wpkt.intf:
                            getsrc = intf.ethaddr
                            break
                    wpkt.packet[0].src = getsrc
                    wpkt.packet[0].dst = arp_table[ip]
                    self.net.send_packet(wpkt.intf,wpkt.packet)
                    log_info (f"Send packet {wpkt.packet} to {intf.name}")
                    wait_reply.remove(wpkt)
                    continue
            if wpkt.send_count == 5 and time.time()-wpkt.send_time>1:
                wait_reply.remove(wpkt)
                print("we remove a wait pkt")
                continue
            elif wpkt.send_count < 5 and time.time()-wpkt.send_time>1:
                print("now get in <5 and >1")
                for intf in all_intf:
                    if intf.name == wpkt.intf:
                        print(" We have find a interface of match!!!")
                        arp_packet = create_ip_arp_request(intf.ethaddr,intf.ipaddr,wpkt.dstip)
                        self.net.send_packet(intf.name,arp_packet)
                        log_info (f"Send a arp packet {arp_packet} to {intf.name}")
                        wpkt.send_count += 1
                        wpkt.send_time = time.time()
                        break
                        
            
                        
                        
                        

                    
                    

    ...

    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''

        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)

            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
        
        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()
