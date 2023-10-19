#!/usr/bin/python3
# 
# Republic of Ireland
# Munster Technological University
# Department of Computer Science
# Student: Jose Lo Huang
#
# Python Script net_recon.py
# Creation Date: 13/11/2021
# Updates:
# 14/11/2021 - Add functions passive_scan and active_recon 
# 15/11/2021 - Add exceptions, comments, edge cases and testing
# 
# This code monitors network hosts in both active or passive mode depending 
# on the user selection.
#

#
# Import the required packages
# 

import sys
from scapy.all import *

#
# This function shows the header of the program and provide the exit method. 
#

def header():
  print("=================================================================")
  print("Network Tool net_recon.py v1.0 powered by Python3 and Scapy v2.  ")
  print("Author: Jose Lo Huang. All rights reserved using the MIT License.")
  print("Complete instructions on the README.txt file. Hit Ctrl+C to exit.")
  print("=================================================================")

#
# This function shows the tool usage to the user.
#

def help():
  print("\n  \
         Network Tool net_recon.py \n \
        ")
  print("Usage: sudo ./net_recon.py {-i|--iface} <interface_name> <mode>")
  print()
  print("<interface_name>: The name of the network interface to monitor.")
  print("<mode>: The mode to be used. Valid values:")
  print("-a or --active for active mode")
  print("-p or --passive for passive mode")
  print()
  print("Example: ./net_recon.py -i enp0s3 --active")
  print() 
  exit()

#
# This function checks if the user arguments are correct.
# Input:
# arguments  - The argument list provided by the user
# valid_args - The valid values to be used as flags
# new_values - The dictionary where the user values will be stored
#

def check_args(args, valid_args, new_values):
  # If the user didn't provide the correct arguments, then show the help
  if (args[1] == '-i' or args[1] == '--iface') and \
     (args[3] in valid_args):
    new_values['iface'] = args[2]
    new_values['mode'] = args[3]
    return 0
  else:
    help()
    return 1

# 
# This function checks if the network interface provided by the user exists or not.
# Input:
# new_values - The dictionary with the session info to get the interface name.
#  

def check_iface(new_values):
  if new_values['iface'] not in get_if_list():
    print("The interface chosen doesn't exists on this host or you don't have proper permissions.")  
    exit()
  else:
    return True

# 
# This function passively monitor the ARP traffic. 
# If the ARP packet has the op code 2 (is-at), then it will 
# store the IP address and MAC address, and print them on the screen.
# References: https://scapy.readthedocs.io/en/latest/usage.html
# Input:
# arp_cache  - The dictionary with all the ARP cache table
# new_values - The dictionary with the session values
# 

def passive_scan(arp_cache, new_values): 
  def arp_monitor_callback(pkt):
    # Filter only ARP packets with op code 2 (is-at)
    if ARP in pkt and pkt[ARP].op == 2: 
      print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
      # If IP exists on the table then just append the new MACs
      if pkt[ARP].psrc in arp_cache:
        if pkt[ARP].hwsrc not in (arp_cache[pkt[ARP].psrc]): 
          (arp_cache[pkt[ARP].psrc]).append(pkt[ARP].hwsrc)
      # If IP doesn't exists on the table then add it
      else:
        arp_cache[pkt[ARP].psrc] = [pkt[ARP].hwsrc]
      print("MAC history for ", pkt[ARP].psrc)
      print(arp_cache[pkt[ARP].psrc])
      return pkt.sprintf("%ARP.psrc% discovered on %ARP.hwsrc%")
  try:
    # Sniff all ARP packets on the iface provided
    sniff(iface=(new_values['iface']), prn=arp_monitor_callback, filter="arp")
  except:
    print("There was an issue with the sniff command.")
    print("Maybe you are not runnning the script as root or with sudo.")
    exit()
  return 0

# 
# This function actively check the actives host in the /24 subnet.
# It uses the ICMP request/reply to validate what hosts are active.
# References:
# https://scapy.readthedocs.io/en/latest/usage.html
# https://scapy.readthedocs.io/en/latest/routing.html
# https://scapy.readthedocs.io/en/latest/api/scapy.interfaces.html
# Input:
# new_values - The dictionary with the network interface name
# 

def active_recon(new_values):
  # Fetch IP address for the iface 
  ip = get_if_addr(new_values['iface'])
  separator = "."
  # Get the /24 network part from the IP
  network = separator.join(ip.split(separator, 3)[:-1])
  active_hosts = []
  # Iterate over all the 256 hosts from the /24 network
  for i in range(0,256):
    host = network+"."+str(i)
    print("Sending ICMP to "+host)
    try:
      # Send an ICMP message to each host
      ans = sr1(IP(dst=host)/ICMP(), timeout=5)
    except:
      print("There was an issue with the sr1 command.") 
      print("Maybe you are not running the script as root or with sudo.")
      exit()
    # Store only the hosts that reply to the ICMP message
    if ans is not None:
      active_hosts.append(host)
  print("The Active Hosts in the /24 Network are:")
  for host in active_hosts:
    print(host) 
  return 0

#
# Main program
# 

def main():
  # Valid Modes (Active and Passive)
  valid_args = ['-a','--active','-p','--passive']
  # Dictionary to store the values for this session
  new_values = {}
  # Dictionary to store the ARP cache table
  arp_cache = {}
  # Check if the arguments are correct
  if len(sys.argv) == 4:
    check_args(sys.argv, valid_args, new_values)
  else:
    help()
  # Check if the interface exists on the current host
  check_iface(new_values)
  # Print header
  header()
  print("Your input values are: ", new_values)
  # Run the program in active or passive mode
  if new_values['mode'] == '-p' or new_values['mode'] == '--passive':
    print("Passive Mode")
    passive_scan(arp_cache, new_values)
  else:
    print("Active Mode")
    active_recon(new_values)
  return 0

#
# Run the main program
#

main()





