#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class ForwardingTableItem:
    def __init__(self,ipaddr,mask,nexthop,interface):
        self.ipaddr = IPv4Address(ipaddr)
        self.mask = IPv4Address(mask)
        self.nexthop = IPv4Address(nexthop)
        self.interface = interface
    
def prefix_len(item):
    netaddr = IPv4Network(f'{item.ipaddr}/{item.mask}',strict=False)
    return netaddr.prefixlen

class ForwardingTable:
    def __init__(self,interfaces):
        # from router interfaces
        self.table = [ForwardingTableItem(intf.ipaddr,intf.netmask,'0.0.0.0',intf.name) \
                        for intf in interfaces]
        # from file
        with open('forwarding_table.txt') as f:
            for line in f.readlines():
                line = line.strip('\n')
                ipaddr,mask,nexthop,interface = line.split(' ')
                self.table.append(ForwardingTableItem(ipaddr,mask,nexthop,interface))
        # sort forwarding table
        self.table.sort(key=prefix_len,reverse=True)
        # print Forwarding Table
        log_info("############### Forwarding Table ################")
        for item in self.table:
            log_info(f"# {item.ipaddr}\t{item.mask}\t{item.nexthop}\t{item.interface}")
        log_info("#################################################\n")
  
    def search(self,ipaddr):
        for item in self.table:
            prefixnet = IPv4Network(f'{item.ipaddr}/{item.mask}',strict=False)
            if ipaddr in prefixnet:
                return item
        return None

class WaitingList:
    def __init__(self,intf):
        self.time = time.time()
        self.trycnt = 5
        self.intf = intf
        self.packets = []

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces = self.net.interfaces()
        self.ipaddrs = [intf.ipaddr for intf in self.interfaces]
        self.ethaddrs = [intf.ethaddr for intf in self.interfaces]
        # some tables
        self.arptable = {}
        self.forwardingtable = ForwardingTable(self.interfaces)
        self.waitingtable = {}

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, ifaceName, packet = recv
        # TODO: your logic here
        log_info (f"Received packet {packet} on {ifaceName}")
        # get headers
        ethheader = packet.get_header(Ethernet)
        arpheader = packet.get_header(Arp)
        ipheader = packet.get_header(IPv4)
        # Drop the packet with Ethernet destination neither a broadcast address 
        # nor the MAC of the incoming port.
        if ethheader and ethheader.dst != "ff:ff:ff:ff:ff:ff" \
                     and ethheader.dst != self.net.interface_by_name(ifaceName).ethaddr:
            return
        # Drop the packet with VLAN
        if ethheader.ethertype == EtherType.x8021Q:
            return
        # Only process the ARP packet when its destination IP is held by a port of the router.
        if arpheader and arpheader.targetprotoaddr in self.ipaddrs:
            # Cached ARP Table
            if arpheader.operation == ArpOperation.Request or arpheader.senderhwaddr != "ff:ff:ff:ff:ff:ff":
                self.arptable[arpheader.senderprotoaddr] = arpheader.senderhwaddr
                # print ARP Table
                log_info("######################## ARP Table Updated ############################")
                for ip,mac in self.arptable.items():
                    log_info(f"# IP({ip})\tMAC({mac})")
                log_info("#######################################################################")
            # Handle ARP packet
            if arpheader.targetprotoaddr in self.ipaddrs:
                # Handle ARP request
                if arpheader.operation == ArpOperation.Request:
                    intf = self.net.interface_by_name(ifaceName)
                    reply_mac = self.net.interface_by_ipaddr(arpheader.targetprotoaddr).ethaddr
                    arp_reply = create_ip_arp_reply(reply_mac, arpheader.senderhwaddr, \
                                arpheader.targetprotoaddr, arpheader.senderprotoaddr)
                    log_info (f"Sending packet {arp_reply} to {intf.name}")
                    self.net.send_packet(intf, arp_reply)
                # Handle ARP reply
                elif arpheader.operation == ArpOperation.Reply:
                    if arpheader.senderhwaddr != "ff:ff:ff:ff:ff:ff":
                        ipaddr,ethaddr = arpheader.senderprotoaddr,arpheader.senderhwaddr
                        if len(self.waitingtable[ipaddr].packets) > 0:
                            intf = self.waitingtable[ipaddr].intf
                            e = Ethernet(src=intf.ethaddr,dst=ethaddr,ethertype=EtherType.IPv4)
                            for waiting_packet in self.waitingtable[ipaddr].packets:
                                waiting_packet[0] = e
                                log_info (f"Sending packet {waiting_packet} to {intf.name}")
                                self.net.send_packet(intf,waiting_packet)
                            self.waitingtable[ipaddr].packets.clear()
                            self.waitingtable[ipaddr].trycnt = 5
        if ipheader:
            # Drop the packet for the router itself.
            # TODO: handle in lab 5
            if ipheader.dst not in self.ipaddrs:
                packet[IPv4].ttl -= 1
                # Process the packet not expired.
                # TODO: handle in lab 5
                if packet[IPv4].ttl > 0:
                    item = self.forwardingtable.search(packet[IPv4].dst)
                    # Drop the packet if there is no match in the table.
                    # TODO: handle in lab 5
                    if item:
                        intf = self.net.interface_by_name(item.interface)
                        # The IP address 0.0.0.0 means that if a packet's destination IP matches this network address, 
                        # just throw the packet out of this interface, expecting that the next hop is the destination.
                        dstip = item.nexthop
                        if dstip == IPv4Address('0.0.0.0'):
                            dstip = packet[IPv4].dst
                        # search ARP Table for dst mac
                        if dstip in self.arptable:
                            dstmac = self.arptable[dstip]
                            packet[0] = Ethernet(src=intf.ethaddr,dst=dstmac,ethertype=EtherType.IPv4)
                            log_info (f"Sending packet {packet} to {intf.name}")
                            self.net.send_packet(intf,packet)
                        # send ARP request for dst mac
                        else:
                            if dstip not in self.waitingtable:
                                self.waitingtable[dstip] = WaitingList(intf)
                            if len(self.waitingtable[dstip].packets) == 0:
                                arp_request = create_ip_arp_request(intf.ethaddr,intf.ipaddr,dstip)
                                log_info (f"Sending packet {arp_request} to {intf.name}")
                                self.net.send_packet(intf, arp_request)
                                self.waitingtable[dstip].time = time.time()
                                self.waitingtable[dstip].trycnt -= 1
                            self.waitingtable[dstip].packets.append(packet)

    def handle_waitinglist(self):
        for ip,wtlst in self.waitingtable.items():
            if len(wtlst.packets) > 0 and time.time() - wtlst.time >= 1:
                # Retransimission
                if wtlst.trycnt > 0:
                    arp_request = create_ip_arp_request(wtlst.intf.ethaddr,wtlst.intf.ipaddr,ip)
                    log_info (f"Sending packet {arp_request} to {wtlst.intf.name}")
                    self.net.send_packet(wtlst.intf, arp_request)
                    self.waitingtable[ip].time = time.time()
                    self.waitingtable[ip].trycnt -= 1
                # Drop packets
                else:
                    self.waitingtable[ip].trycnt = 5
                    self.waitingtable[ip].packets.clear()


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        while True:
            try:
                self.handle_waitinglist()
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
