/*
*	Copyright (C) 2006 prijkes

*	This program is free software; you can redistribute it and/or
*	modify it under the terms of the GNU General Public License
*	as published by the Free Software Foundation; either version 2
*	of the License, or (at your option) any later version.

*	This program is distributed in the hope that it will be useful,
*	but WITHOUT ANY WARRANTY; without even the implied warranty of
*	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*	GNU General Public License for more details.

*	You should have received a copy of the GNU General Public License
*	along with this program; if not, write to the Free Software
*	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
#ifndef _NetworkStructs_H_
#define _NetworkStructs_H_
#include "NetworkShortStructs.h"
#include "NetworkEnums.h"

// Network layer structs
// all numbers are BITS if not specified
typedef struct ETHERNET_HDR
{
	MACADDR dst_mac;	// destination mac address (48)
	MACADDR src_mac;	// source mac address (48)
	u_short type;		// type (16) ??
						//	--------- +
						//		112/8 = 14 bytes
} ETHERNET_HDR;

typedef struct ARP_HDR
{
	u_short hw_type;		// Hardware type (16)
	u_short protocol;		// Protocol type (16)
	u_char hw_len;			// Hardware length ?? (8)
	u_char prot_len;		// Protocol length ?? (8)
	u_short opcode;			// Opcode (16) 1 is request, 2 = reply
	MACADDR src_hw;			// Source hardware address (MAC) (32)
	IP4ADDR src_ip;			// Source ip address (32)
	MACADDR dst_hw;			// Dest hardware address (MAC) (32)
	IP4ADDR dst_ip;			// Dest ip address (32)
							//	--------- +
							//		224/8 = 28 bytes
} ARP_HDR;

typedef struct IP4HDR
{
	u_char ver_ihl;				// IP packet header version (4) +
								// internet header lenght (4)
								// IHL = IP header length
	u_char tos;					// type of service (8)
	u_short total_len;			// total packet length (8)
	u_short id;					// identification (16)
	u_short flags_fragoffset;	// flags (3) +
								// fragment offset (13)
	u_char ttl;					// time to live (8)
	u_char protocol;			// protocol type (8)
	u_short hdr_checksum;		// header checksum (16)
	IP4ADDR src_ip;				// source ip address (4*8 = 32)
	IP4ADDR dst_ip;				// bytes destination ip address (4*8 = 32)
	u_int options_pad;			// options + padding (32)
								//	------------- +
								//			192/8 = 24 bytes
} IP4_HDR;


// Transport layer structures
typedef struct TCP_HDR
{
	u_short src_port;			// source port (16)
	u_short dst_port;			// destination port (16)
	u_int seqno;				// sequence number (32)
	u_int ackno;				// acknowledgment number (32)
	u_char dre;					// data offset (4) + reserved (3) + ECN (1)
	u_char ctrl_bits;			// ECN (2) + control bits (6)
								// ECN: cwr, ecn
								//		cwr: Congestion Window Reduced
								//		ecn: ECN-Echo
								// Control bits: urg, ack, psh, rsh, syn, fin
								//		urg: Urgent pointer
								//		ack: Acknowledge
								//		psh: Push, sends data to the application
								//		rsh: Reset flag
								//		syn: Synchronize sequence numbers to start a connection
								//		fin: Finish flag "fin"
	u_short window;				// window (16)
	u_short checksum;			// checksum (16)
	u_short urgent;				// urgent (16)
	u_int options_pad;			// options + padding (32)
								//	------------- +
								//			192/8 = 24 bytes
} TCP_HDR;

typedef struct UDP_HDR
{
	u_short		src_port;		// Source port (16)
	u_short		dst_port;		// Destination port (16)
	u_short		len;			// Datagram length (16)
	u_short		crc;			// Checksum (16)
								//	------------- +
								//			64/8 = 8 bytes
} UDPHDR;

typedef struct IGMP_HDR
{
	u_char ver_type;			// Version (4) + Type (4)
	u_char unused;				// Not used (8)
	u_short checksum;			// Checksum (16)
	u_int group_addr;			// Group Address (32)
								//	------------ +
								//			64/8 = 8 bytes
} IGMP_HDR;


// Other structs
typedef struct s_HardwareTypes
{
//  http://www.iana.org/assignments/arp-parameters
	int hw_type;
	char* hw_name;
	int hw_len;
	char* reference;
} s_HardwareTypes; static s_HardwareTypes HardwareTypes[] = {
	{0, 0, 0},
	{1, "Ethernet (10Mb)", 6, "JBP"},
	{2, "Experimental Ethernet (3Mb)", 0, "JBP"},
	{3, "Amateur Radio AX.25", 0, "PXK"},
	{4, "Proteon ProNET Token Ring", 0, "Doria"},
	{5, "Chaos", 0, "GXP"},
	{6, "IEEE 802 Networks", 0, "JBP"},
	{7, "ARCNET", 0, "JBP"},
	{8, "Hyperchannel", 0, "JBP"},
	{9, "Lanstar", 0, "TU"},
	{10, "Autonet Short Address", 0, "MXB1"},
	{11, "LocalTalk", 0, "JKR1"},
	{12, "LocalNet (IBM PCNet or SYTEK LocalNET)", 0, "JXM"},
	{13, "Ultra link", 0, "RXD2"},
	{14, "SMDS", 0, "GXC1"},
	{15, "Frame Relay", 0, "AGM"},
	{16, "Asynchronous Transmission Mode (ATM)", 0, "JXB2"},
	{17, "HDLC", 0, "JBP"},
	{18, "Fibre Channel", 0, "RFC-ietf-imss-ip-over-fibre-channel-03.txt"},
	{19, "Asynchronous Transmission Mode (ATM)", 0, "RFC2225"},
	{20, "Serial Line", 0, "JBP"},
	{21, "Asynchronous Transmission Mode (ATM)", 0, "MXB1"},
	{22, "MIL-STD-188-220", 0, "Jensen"},
	{23, "Metricom", 0, "Stone"},
	{24, "IEEE 1394.1995", 0, "Hattig"},
	{25, "MAPOS", 0, "Maruyama"},
	{26, "Twinaxial", 0, "Pitts"},
	{27, "EUI-64", 0, "Fujisawa"},
	{28, "HIPARP", 0, "JMP"},
	{29, "IP and ARP over ISO 7816-3", 0, "Guthery"},
	{30, "ARPSec", 0, "Etienne"},
	{31, "IPsec tunnel", 0, "RFC3456"},
	{32, "InfiniBand (TM)", 0, "RFC-ietf-ipoib-ip-over-infiniband-09.txt"},
	{33, "TIA-102 Project 25 Common Air Interface (CAI)", 0, "Anderson"}
};

typedef struct s_NetworkLayers
{
	int id;
	char* short_name;
	char* long_name;
} s_NetworkLayers; static s_NetworkLayers NetworkLayers[] = {
	{XEROX_IDP, "XEROX_IDP", "XEROX NS IDP"},
	{DLOG, "DLOG", "DLOG"},
	//{DLOG, "DLOG", "DLOG"},
	{IPv4, "IPv4", "Internet Protocol version 4"},
	{X75, "X75", "X.75 Internet"},
	{NBS, "NBS", "NBS Internet"},
	{ECMA, "ECMA", "ECMA Internet"},
	{Chaosnet, "Chaosnet", "Chaosnet"},
	{X25_L3, "X25_L3", "X.25 Level 3"},
	{ARP, "ARP", "Address Resolution Protocol"},
	{DRARP, "DRARP", "Dynamic RARP"},
	{RARP, "RARP", "Reverse Address Resolution Protocol"},
	{AARP, "AARP", "AppleTalk Address Resolution Protocol"},
	{EAPS, "EAPS", "Ethernet Automatic Protection Switching"},
	{IPX, "IPX", "Internet Packet Exchange"},
	{SNMP, "SNMP", "Simple Network Management Protocol"},
	{IPv6, "IPv6", "Internet Protocol version 6"},
	{PPP, "PPP", "Point-to-Point Protocol"},
	{GSMP, "GSMP", "General Switch Management Protocol"},
	{MPLS_U, "MPLS_U", "Multi-Protocol Label Switching (unicast)"},
	{MPLS_M, "MPLS_M", "Multi-Protocol Label Switching (multicast)"},
	{PPPoE_D, "PPPoE_D", "PPP over Ethernet (Discovery Stage)"},
	{PPPoE_P, "PPPoE_P", "PPP over Ethernet (PPP Session Stage)"},
	{LWAPP, "LWAPP", "Light Weight Access Point Protocol"},
	{LLDP, "LLDP", "Link Layer Discovery Protocol"},
	{EAPOL, "EAPOL", "EAP over LAN"},
	{reserved, "Reserved", "Reserved"}
};

typedef struct s_TransportLayers
{
	int id;
	char* short_name;
	char* long_name;
} s_TransportLayers; static s_TransportLayers TransportLayers[] = {
	{HOPOPT, "HOPOPT", "IPv6 Hop-by-Hop Option"},
	{ICMP, "ICMP", "Internet Control Message Protocol"},
	{IGAP, "IGAP", "IGMP for user Authentication Protocol"},
	{IGMP, "IGMP", "Internet Group Management Protocol"},
	{RGMP, "RGMP", "Router-port Group Management Protocol"},
	{GGP, "GGP", "Gateway to Gateway Protocol"},
	{IPIP, "IPIP", "IP in IP encapsulation"},
	{ST, "ST", "Internet Stream Protocol"},
	{TCP, "TCP", "Transmission Control Protocol"},
	{UCL, "UCL", "UCL/CBT"},
	{EGP, "EGP", "Exterior Gateway Protocol"},
	{IGRP, "IGRP", "Interior Gateway Routing Protocol"},
	{BBN, "BBN", "BBN RCC Monitoring"},
	{NVP, "NVP", "Network Voice Protocol"},
	{PUP, "PUP", "PUP"},
	{ARGUS, "ARGUS", "ARGUS"},
	{EMCON, "EMCON", "Emission Control Protocol"},
	{XNET, "XNET", "Cross Net Debugger"},
	{Chaos, "Chaos", "Chaos"},
	{UDP, "UDP", "User Datagram Protocol"},
	{TMux, "TMux", "Transport Multiplexing Protocol"},
	{DCN, "DCN", "Measurement Subsystems"},
	{HMP, "HMP", "Host Monitoring Protocol"},
	{PRM, "PRM", "Packet Radio Measurement"},
	{XEROX, "XEROX", "XEROX NS IDP"},
	{Trunk1, "Trunk1", "Trunk-1"},
	{Trunk2, "Trunk2", "Trunk-2"},
	{Leaf1, "Leaf1", "Leaf-1"},
	{Leaf2,	"Leaf2", "Leaf-2"},
	{RDP, "RDP", "Reliable Data Protocol"},
	{IRTP, "IRTP", "Internet Reliable Transaction Protocol"},
	{ISO, "ISO", "ISO Transport Protocol Class 4"},
	{NETBLT, "NETBLT", "Network Block Transfer"},
	{MFE, "MFE", "MFE Network Services Protocol"},
	{MERIT, "MERIT", "MERIT Internodal Protocol"},
	{SEP, "SEP", "Sequential Exchange Protocol"},
	{DCCP, "DCCP", "Datagram Congestion Control Protocol"},
	{TPCP, "TPCP", "Third Party Connect Protocol"},
	{IDPR, "IDPR", "Inter-Domain Policy Routing Protocol"},
	{XTP, "XTP", "Xpress Transfer Protocol"},
	{DDP, "DDP", "Datagram Delivery Protocol"},
	//{IDPR, "IDPR", "Control Message Transport Protocol"},
	{TP, "TP", "TP++ Transport Protocol"},
	{IL, "IL", "IL Transport Protocol"},
	{IPv6_4, "IPv6-IPv4", "IPv6 over IPv4"},
	{SDRP, "SDRP", "Source Demand Routing Protocol"},
	{IPv6_rh, "IPv6_RH", "IPv6 Routing Header"},
	{IPv6_fh, "IPv6_FH", "IPv6 Fragment Header"},
	//{IDRP, "IDRP", "Inter-Domain Routing Protocol"},
	{RSVP, "RSVP", "Reservation Protocol"},
	{GRE, "GRE", "General Routing Encapsulation"},
	{MHRP, "MHRP", "Mobile Host Routing Protocol"},
	{BNA, "BNA", "BNA"},
	{ESP, "ESP", "Encapsulating Security Payload"},
	{AH, "AH", "Authentication Header"},
	{INLS, "INLS", "Intergrated Net Layer Security TUBA"},
	{IP_e, "IP_E", "IP with Encryption"},
	{NARP, "NARP", "NBMA Address Resolution Protocol"},
	{MEP, "MEP", "Minimal Encapsulation Protocol"},
	{TLSP, "TLSP", "Transport Layer Security Protocol using Kryptonet key management"},
	{SKIP, "SKIP", "SKIP"},
	{ICMPv6, "ICMPv6", "Internet Control Message Protocol for IPv6"},
	{MLD, "MLD", "Multicast Listener Discovery"},
	{IPv6_nnh, "IPv6_NNH",	"IPv6 No Next Header"},
	{IPv6_do, "IPv6_DO", "IPv6 Destination Options"},
	{int_prot, "int_prot", "Any host internet protocol"},
	{CFTP, "CFTP", "CFTP"},
	{lan, "lan", "Any local (area?) network"},
	{SATNET, "SATNET", "SATNET and Backroom EXPAK"},
	{Kryptolan, "Kryptolan", "Kryptolan"},
	{RVDP, "RVDP", "MIT Remote Virtual Disk Protocol"},
	{IPPC, "IPPC", "Internet Pluribus Packet Core"},
	{file_sys, "file_sys", "Any distributed file system"},
	{SATNET_M, "SATNET_M", "SATNET Monitoring"},
	{VISA, "VISA", "VISA Protocol"},
	{IPCU, "IPCU", "Internet Packet Core Utility"},
	{CPNE, "CPNE", "Computer Protocol Network Executive"},
	{CPHB, "CPHB", "Computer Protocol Heart Beat"},
	{WSN, "WSN", "Wang Span Network"},
	{PVP, "PVP", "Packet Video Protocol"},
	{BSM, "BSM", "Backroom SATNET Monitoring"},
	{SUNNDP, "SUNNDP", "SUN ND PROTOCOL-Temporary"},
	{WM, "WM", "WIDEBAND Monitoring"},
	{WE, "WE", "WIDEBAND EXPAK"},
	{ISO_IP, "ISO_IP", "ISO-IP"},
	{VMTP, "VMTP", "Versatile Message Transaction Protocol"},
	{SVMTP, "SVMTP", "SECURE-VMTP"},
	{VINES, "VINES", "VINES"},
	{TTP, "TTP", "TTP"},
	{N_IGP, "N_IGP", "NSFNET-IGP"},
	{DGP, "DGP", "Dissimilar Gateway Protocol"},
	{TCF, "TCF", "TCF"},
	{EIGRP, "EIGRP", "EIGRP"},
	{OSPF, "OSPF", "Open Shortest Path First Routing Protocol"},
	{MOSPF, "MOSPF", "Multicast Open Shortest Path First"},
	{SRPCP, "SRPCP", "Sprite RPC Protocol"},
	{LARP, "LARP", "Locus Address Resolution Protocol"},
	{MTP, "MTP", "Multicast Transport Protocol"},
	{AX25, "AX25", "AX.25"},
	{IP_IPEP, "IP_IPEP", "IP-within-IP Encapsulation Protocol"},
	{MICP, "MICP", "Mobile Internetworking Control Protocol"},
	{EtherIP, "EtherIP", "EtherIP"},
	{EH, "EH", "Encapsulation Header"},
	{PES, "PES", "Any private encryption scheme"},
	{GMTP, "GMTP", "GMTP"},
	{IFMP, "IFMP", "Ipsilon Flow Management Protocol"},
	{PNNP, "PNNP", "PNNI over IP"},
	{PIM, "PIM", "Protocol Independent Multicast"},
	{ARIS, "ARIS", "ARIS"},
	{SCPS, "SCPS", "SCPS"},
	{QNX, "QNX", "QNX"},
	{AN, "AN", "Active Networks"},
	{IPPCP, "IPPCP", "IP Payload Compression Protocol"},
	{SNP, "SNP", "Sitara Networks Protocol"},
	{CPP, "CPP", "Compaq Peer Protocol"},
	{IPX_IP, "IPX_IP", "IPX in IP"},
	{VRRP, "VRRP", "Virtual Router Redundancy Protocol"},
	{PGM, "PGM", "Pragmatic General Multicast"},
	{hop0_p, "hop0_p", "Any 0-hop protocol"},
	{L2TP, "L2TP", "Level 2 Tunneling Protocol"},
	{DDX, "DDX", "D-II Data Exchange"},
	{LATP, "LATP", "Interactive Agent Transfer Protocol"},
	//{ST, "ST", "Schedule Transfer"},
	{SRP, "SRP", "SpectraLink Radio Protocol"},
	{UTI, "UTI", "UTI"},
	{SMP, "SMP", "Simple Message Protocol"},
	{SM, "SM", "SM"},
	{PTP, "PTP", "Performance Transparency Protocol"},
	{ISI_IPv4, "ISI_IPv4", "ISIS over IPv4"},
	{FIRE, "FIRE", "FIRE"},
	{CRTP, "CRTP", "Combat Radio Transport Protocol"},
	{CRUDP, "CRUDP", "Combat Radio User Datagram"},
	{SSCOPMCE, "SSCOPMCE", "SSCOPMCE"},
	{IPLT, "IPLT", "IPLT"},
	{SPS, "SPS", "Secure Packet Shield"},
	{PIPE, "PIPE", "Private IP Encapsulation within IP"},
	{SCTP, "SCTP", "Stream Control Transmission Protocol"},
	{Fibre_c, "Fibre_c", "Fibre Channel"},
	//{RSVP, "RSVP", "RSVP-E2E-IGNORE"},
	{MH, "MH", "Mobility Header"},
	{UDP_Lite, "UDP_Lite", "Lightweight User Datagram Protocol"},
	{MPLS, "MPLS", "MPLS in IP"},
	{Reserved, "Reserved", "reserved"}
};

typedef struct s_ARP_Opcodes
{
	int id;
	char* name;
} s_ARP_Opcodes; static s_ARP_Opcodes ARP_Opcodes[] = {
	{0, 0},
	{1, "ARP Request"},
	{2, "ARP Reply"},
	{3, "Request Reverse (RARP)"},
	{4, "Reply Reverse (RARP)"},
	{5, "DRARP Request"},
	{6, "DRARP Reply"},
	{7, "DRARP Error"},
	{8, "InARP Request"},
	{9, "InARP Reply"},
	{10, "ARP NAK"},
	{11, "MARS Request"},
	{12, "MARS Multi"},
	{13, "MARS MServ"},
	{14, "MARS Join"},
	{15, "MARS Leave"},
	{16, "MARS NAK"},
	{17, "MARS Unserv"},
	{18, "MARS SJoin"},
	{19, "MARS SLeave"},
	{20, "MARS Grouplist Request"},
	{21, "MARS Grouplist Reply"},
	{22, "MARS Redirect Map"},
	{23, "MAPOS UNARP"}
};

#endif	// ifndef _NetworkStructs_H_