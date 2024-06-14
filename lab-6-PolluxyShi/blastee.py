#!/usr/bin/env python3

import time
import threading
from struct import pack
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blastee:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasterIp,
            num
    ):
        self.net = net
        # TODO: store the parameters
        self.blasterIp = blasterIp
        self.num = num
        ...

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug(f"I got a packet from {fromIface}")
        log_debug(f"Pkt: {packet}")

        # construct headers
        eth = Ethernet(src="20:00:00:00:00:01",dst="40:00:00:00:00:02",ethertype=EtherType.IPv4)
        ip = IPv4(src="192.168.200.1",dst=self.blasterIp,protocol=IPProtocol.UDP)
        udp = UDP()
        seq = RawPacketContents(raw=packet[3].to_bytes()[:4])
        pkt = eth + ip + udp + seq

        payLoadLen = int.from_bytes(packet[3].to_bytes()[4:6],byteorder='big')
        if payLoadLen >= 8:
            pkt.add_payload(packet[3].to_bytes()[6:14])
        else:
            pkt.add_payload(packet[3].to_bytes()[6:]+bytes([0]*(8-payLoadLen)))

        # send ACK
        self.net.send_packet("blastee-eth0", pkt)

    def start(self):
        '''A running daemon of the blastee.
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

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blastee = Blastee(net, **kwargs)
    blastee.start()
