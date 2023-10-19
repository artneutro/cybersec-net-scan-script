Republic of Ireland
Munster Technological University
Department of Computer Science
Student: Jose Lo Huang

Python Script net_recon.py
Creation Date: 13/11/2021
Updates:
14/11/2021 - Add functions passive_scan and active_recon 
15/11/2021 - Add exceptions, comments, edge cases and testing

This code monitors network traffic in both active or passive mode depending on the user selection.

1. Passive Mode

In this mode the script will capture the ARP traffic from the 
network interface provided and will filter only those with the 
op code 2 (is-at) to store a local ARP cache table. It will 
include all the MAC addresses history for each IP. The script 
shows each IP and the MAC address history each time it gets a 
filtered packet. 

2. Active Mode

In this mode the script will send an ICMP message to each host 
in the /24 network of the network interface provided. It will 
store all the active hosts (those who replies). The script 
shows all the active hosts at the end of the scan session.

=============================================================
Usage: 

sudo ./net_recon.py {-i|--iface} <interface_name> <mode>

<interface_name>: The name of the network interface to monitor.
<mode>: The mode to be used. Valid values:
-a or --active for active mode
-p or --passive for passive mode

Example: sudo ./net_recon.py -i enp0s3 --active

=============================================================





