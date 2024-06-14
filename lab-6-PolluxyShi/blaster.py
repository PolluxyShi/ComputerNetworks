#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp = blasteeIp
        self.num = num
        self.length = length
        self.senderWindow = senderWindow
        self.timeout = timeout
        self.recvTimeout = recvTimeout
        self.LHS = 1
        self.RHS = 0
        self.time = time.time()
        self.packets = {}
        self.wl = []

        self.baseTime = time.time()
        self.reTXnum = 0
        self.TOnum = 0
        self.throughput = 0
        self.goodput = 0

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        log_debug(f"Pkt: {packet}")

        # ACK
        seq = int.from_bytes(packet[3].to_bytes()[:4],byteorder='big')
        if seq in self.packets:
            if seq == list(self.packets.keys())[0]:
                self.time = time.time()
            del self.packets[seq]

        if len(self.packets) > 0:
            self.LHS = list(self.packets.keys())[0]
        else:
            self.LHS = self.RHS + 1
            # print stats
            log_debug(f"Total TX time: {self.time-self.baseTime} s")
            log_debug(f"Number of reTX: {self.reTXnum}")
            log_debug(f"Number of TOs: {self.TOnum}")
            log_debug(f"Throughput: {self.throughput/(self.time-self.baseTime)} Bps")
            log_debug(f"Goodput: {self.goodput/(self.time-self.baseTime)} Bps")
        

    def handle_no_packet(self):
        log_debug("Didn't receive anything")

        # process old packet
        if len(self.packets) > 0 and (time.time() - self.time) * 1000 > float(self.timeout):
            self.TOnum += 1
            for i in self.packets.keys():
                if i not in self.wl:
                    self.wl.append(i)

        NRT = True # not retransmit
        while NRT and len(self.wl) > 0:
            seq = self.wl[0]
            del self.wl[0]
            if seq in self.packets:
                self.net.send_packet("blaster-eth0", self.packets[seq])
                NRT = False
                self.reTXnum += 1
                self.throughput += int.from_bytes(self.packets[seq][4].data,byteorder='big')
                if seq == self.LHS:
                    self.time = time.time()

        # send new packet
        if NRT and self.RHS - self.LHS + 1 < int(self.senderWindow) and self.RHS < int(self.num):
            if self.RHS == 0:
                self.baseTime = time.time()

            # Creating the headers for the packet
            pkt = Ethernet() + IPv4() + UDP()
            pkt[0].src="10:00:00:00:00:01"
            pkt[0].dst="40:00:00:00:00:01"
            pkt[0].ethertype=EtherType.IPv4
            pkt[1].src = "192.168.100.1"
            pkt[1].dst = self.blasteeIp
            pkt[1].protocol = IPProtocol.UDP

            # Do other things here and send packet
            seq = self.RHS + 1
            
            # construct packet
            pkt += RawPacketContents(raw=(seq).to_bytes(4,byteorder='big'))
            pkt += RawPacketContents(raw=(int(self.length)).to_bytes(2,byteorder='big'))

            intstream = [randint(0,255) for _ in range(int(self.length))]
            string = str(intstream)
            pkt += RawPacketContents(raw=string)

            # send packet
            self.net.send_packet("blaster-eth0", pkt)
            self.packets[seq] = pkt
            self.RHS = seq
            self.throughput += int.from_bytes(pkt[4].data,byteorder='big')
            self.goodput += int.from_bytes(pkt[4].data,byteorder='big')
        

    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
