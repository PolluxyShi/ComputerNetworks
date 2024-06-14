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

def isICMPErrorMessage(packet):
    return packet[IPv4].protocol == IPProtocol.ICMP \
            and (packet[ICMP].icmptype == ICMPType.DestinationUnreachable \
            or packet[ICMP].icmptype == ICMPType.TimeExceeded)

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

    def update_ARP_table(self,arpheader):
        if arpheader.operation == ArpOperation.Request or arpheader.senderhwaddr != "ff:ff:ff:ff:ff:ff":
            self.arptable[arpheader.senderprotoaddr] = arpheader.senderhwaddr
            # print ARP Table
            log_info("######################## ARP Table Updated ############################")
            for ip,mac in self.arptable.items():
                log_info(f"# IP({ip})\tMAC({mac})")
            log_info("#######################################################################")
    
    def handle_ARP_Request(self,arpheader,ifaceName):
            intf = self.net.interface_by_name(ifaceName)
            reply_mac = self.net.interface_by_ipaddr(arpheader.targetprotoaddr).ethaddr
            arp_reply = create_ip_arp_reply(reply_mac, arpheader.senderhwaddr, \
                        arpheader.targetprotoaddr, arpheader.senderprotoaddr)
            log_info (f"Sending packet {arp_reply} to {intf.name}")
            self.net.send_packet(intf, arp_reply)

    def handle_ARP_Reply(self,arpheader):
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
    
    def forwarding_packet(self,packet,sendErrorMessage = False):
        item = self.forwardingtable.search(packet[IPv4].dst)
        # Process the packet match entry
        if item:
            packet[IPv4].ttl = max(packet[IPv4].ttl-1,0)
            # Process the packet not expired.
            if packet[IPv4].ttl > 0:
                intf = self.net.interface_by_name(item.interface)

                # set srcip of ICMP error message packet from router
                if sendErrorMessage:
                    packet[IPv4].src = intf.ipaddr

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
            else:
                if not isICMPErrorMessage(packet):
                    self.handle_TTL_Expired(packet)
        else:
            if not isICMPErrorMessage(packet):
                self.handle_No_Matching_Entries(packet)

    def handle_No_Matching_Entries(self,packet):
        # remove Ethernet Header 
        index = packet.get_header_index(Ethernet)
        del packet[index]

        # construct ICMP header 
        i = ICMP()
        i.icmptype = ICMPType.DestinationUnreachable
        i.icmpcode = ICMPTypeCodeMap[i.icmptype].NetworkUnreachable
        i.icmpdata.data = packet.to_bytes()[:28]

        # construct IP header
        ip = IPv4()
        ip.src = packet[IPv4].dst ####
        ip.dst = packet[IPv4].src
        ip.protocol = IPProtocol.ICMP
        ip.ttl = 64

        # send Error Message
        pkt = Ethernet() + ip + i
        self.forwarding_packet(pkt,True)

    def handle_TTL_Expired(self,packet):
        # remove Ethernet Header 
        index = packet.get_header_index(Ethernet)
        del packet[index]

        # construct ICMP header 
        i = ICMP()
        i.icmptype = ICMPType.TimeExceeded
        i.icmpcode = ICMPTypeCodeMap[i.icmptype].TTLExpired
        i.icmpdata.data = packet.to_bytes()[:28]

        # construct IP header
        ip = IPv4()
        ip.src = packet[IPv4].dst ####
        ip.dst = packet[IPv4].src
        ip.protocol = IPProtocol.ICMP
        ip.ttl = 64

        # send Error Message
        pkt = Ethernet() + ip + i
        self.forwarding_packet(pkt,True)

    def handle_ARP_Failure(self,packet):
        # remove Ethernet Header 
        index = packet.get_header_index(Ethernet)
        del packet[index]

        # construct ICMP header 
        i = ICMP()
        i.icmptype = ICMPType.DestinationUnreachable
        i.icmpcode = ICMPTypeCodeMap[i.icmptype].HostUnreachable
        i.icmpdata.data = packet.to_bytes()[:28]

        # construct IP header
        ip = IPv4()
        ip.src = packet[IPv4].dst ####
        ip.dst = packet[IPv4].src
        ip.protocol = IPProtocol.ICMP
        ip.ttl = 64

        # send Error Message
        pkt = Ethernet() + ip + i
        self.forwarding_packet(pkt,True)

    def handle_Unsupported_Function(self,packet):
        # remove Ethernet Header 
        index = packet.get_header_index(Ethernet)
        del packet[index]

        # construct ICMP header 
        i = ICMP()
        i.icmptype = ICMPType.DestinationUnreachable
        i.icmpcode = ICMPTypeCodeMap[i.icmptype].PortUnreachable
        i.icmpdata.data = packet.to_bytes()[:28]

        # construct IP header
        ip = IPv4()
        ip.src = packet[IPv4].dst ####
        ip.dst = packet[IPv4].src
        ip.protocol = IPProtocol.ICMP
        ip.ttl = 64

        # send Error Message
        pkt = Ethernet() + ip + i
        self.forwarding_packet(pkt,True)

    def handle_ICMP_packet(self,packet):
        icmpheader = packet.get_header(ICMP)
        if icmpheader.icmptype == ICMPType.EchoRequest:
            self.handle_ICMP_Echo_Request(packet)
    
    def handle_ICMP_Echo_Request(self,packet):
            # construct ICMP header 
            i = ICMP()
            i.icmptype = ICMPType.EchoReply
            i.icmpdata.data = packet[ICMP].icmpdata.data
            i.icmpdata.identifier = packet[ICMP].icmpdata.identifier
            i.icmpdata.sequence = packet[ICMP].icmpdata.sequence

            # construct IP header
            ip = IPv4()
            ip.src = packet[IPv4].dst ####
            ip.dst = packet[IPv4].src
            ip.protocol = IPProtocol.ICMP
            ip.ttl = 64

            # send packet
            echoReplyPkt = Ethernet() + ip + i
            self.forwarding_packet(echoReplyPkt)

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
            self.update_ARP_table(arpheader)
            # Handle ARP packet
            if arpheader.targetprotoaddr in self.ipaddrs:
                # Handle ARP request
                if arpheader.operation == ArpOperation.Request:
                    self.handle_ARP_Request(arpheader,ifaceName)
                # Handle ARP reply
                elif arpheader.operation == ArpOperation.Reply:
                    self.handle_ARP_Reply(arpheader)
        
        if ipheader:
            # Drop the packet for the router itself.
            if ipheader.dst in self.ipaddrs:
                icmpheader = packet.get_header(ICMP)
                if icmpheader:
                    self.handle_ICMP_packet(packet)
                else:
                    self.handle_Unsupported_Function(packet)
            else:
                self.forwarding_packet(packet)
                

    def handle_waitinglist(self):
        failure_pkt = []
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
                    for pkt in wtlst.packets:
                        failure_pkt.append(pkt)
                    self.waitingtable[ip].packets.clear()
                    self.waitingtable[ip].trycnt = 5
        for pkt in failure_pkt:
            if not isICMPErrorMessage(pkt):
                self.handle_ARP_Failure(pkt)


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
