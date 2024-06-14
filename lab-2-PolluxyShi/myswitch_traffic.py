'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *


def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    swtable = {}
    swtable_cap = 5

    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break

        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.src in swtable:
            swtable[eth.src] = (fromIface, swtable[eth.src][1])
            # log_info(f"=== Updata mac:{eth.src} to interface:{fromIface}")
        else:
            if len(swtable) == swtable_cap:
                lowest = 1e7
                for (mac,(_,tfvolume)) in swtable.items():
                    if tfvolume < lowest:
                        lowest = tfvolume
                        evict_mac = mac
                # log_info(f"=== Delete mac:{evict_mac} with lowest traffic:{lowest}")
                del swtable[evict_mac]
            swtable[eth.src] = (fromIface,0)
            # log_info(f"=== Add mac:{eth.src} to interface:{fromIface} with traffict:{0}")
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst in swtable:
                swtable[eth.dst] = (swtable[eth.dst][0], swtable[eth.dst][1]+1)
                # log_info(f"=== Updata mac:{eth.dst} to interface:{swtable[eth.dst][0]} with traffic:{swtable[eth.dst][1]}")
                toIface = swtable[eth.dst][0]
                for intf in my_interfaces:
                    if toIface == intf.name:
                        log_info (f"Sending packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
                        break
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)
            

    net.shutdown()
