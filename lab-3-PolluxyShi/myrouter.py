#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # other initialization stuff here
        self.interfaces = self.net.interfaces()
        self.ipaddrs = [intf.ipaddr for intf in self.interfaces]
        self.arptable = {}

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, ifaceName, packet = recv
        # TODO: your logic here
        log_info (f"Received packet {packet} on {ifaceName}")
        arp = packet.get_header(Arp)
        if arp is None:
            log_info("Received a non-ARP packet?!")
            return
        # Cached ARP Table
        if arp.senderhwaddr != "ff:ff:ff:ff:ff:ff":
            self.arptable[arp.senderprotoaddr] = arp.senderhwaddr
            log_info("############### ARP Table Updated ###############")
            for ip,mac in self.arptable.items():
                log_info(f"# IP({ip})\tMAC({mac})")
            log_info("#################################################\n")
        # Handle ARP request
        if arp.targetprotoaddr in self.ipaddrs:
            log_info("Received a packet intended for me")
            intf = self.net.interface_by_name(ifaceName)
            arp_reply = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
            log_info (f"Sending packet {arp_reply} to {intf.name}")
            self.net.send_packet(intf, arp_reply)

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
