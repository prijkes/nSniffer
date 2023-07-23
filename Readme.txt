
             nSniffer
      Made by prijkes

--------------------------------------

nSniffer is a Command-Line network sniffer written in C++ 
with the help of WinPCap. nSniffer consists of two main parts:
1. A packet sniffer.
2. A packet sender.

There's also a smaller part, which can list your NIC's attachted to your computer
and show the information of it. There are two ways to do this, through the Windows
API GetAdaptersInfo or through the WinPCap API pcap_findalldevs_ex. Both are
supported.

It has also a set of parameters to set the output to your likings, see the 
Parameters.txt for more information about the parameters and howto use them.


-- Packet sniffer
The packet sniffer part of nSniffer can snif packets that are going in and out.
It will snif on the given device/NIC (Network Interface Card).
Currently it can only show the details of 3 Network Layers:
1. IPv4
2. RARP
3. ARP

For IPv4, it can show the details of 3 Transport Layers:
1. IGMP
2. TCP
3. UDP

You can add details of different layers.


-- Packet sender
The packet sender part of nSniffer can send manually created packets to a NIC.
The creation of a packet begins from the transport layer to the data link layer.
That means if you want to send an TCP packet, it gets build like this:
1. Data
2. TCP Header
3. IPv4 Header
4. Ethernet Header

You can specify all the options of a packet, like the control bits of a tcp header,
to the destination/source mac address of the ethernet header.
You don't have to worry about the checksum of the tcp and/or ipv4 header, it gets
calculated by the program and automatically filled in.




-- Usage info
This program is free and released under the GPL, you may not use any of the files
for money making (ie. commercial) purposes.
