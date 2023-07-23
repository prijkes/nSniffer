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
#ifndef _NetworkEnums_H_
#define _NetworkEnums_H_

enum NETWORK_LAYERS
{
//  http://www.iana.org/assignments/ethernet-numbers
	XEROX_IDP = 0x0600,		// XEROX NS IDP
	DLOG = 0x0660,			// DLOG
	//DLOG = 0x0661,		// DLOG
	IPv4 = 0x0800,			// Internet Protocol version 4
	X75 = 0x0801,			// X.75 Internet
	NBS = 0x0802,			// NBS Internet
	ECMA = 0x0803,			// ECMA Internet
	Chaosnet = 0x0804,		// Chaosnet
	X25_L3 = 0x0805,		// X.25 Level 3
	ARP = 0x0806,			// Address Resolution Protocol
	DRARP = 0x8035,			// Dynamic RARP
	RARP = 0x8035,			// Reverse Address Resolution Protocol
	AARP = 0x80F3,			// AppleTalk Address Resolution Protocol
	EAPS = 0x8100,			// Ethernet Automatic Protection Switching
	IPX = 0x8137,			// Internet Packet Exchange
	SNMP = 0x814C,			// Simple Network Management Protocol
	IPv6 = 0x86DD,			// Internet Protocol version 6
	PPP = 0x880B,			// Point-to-Point Protocol
	GSMP = 0x880C,			// General Switch Management Protocol
	MPLS_U = 0x8847,		// Multi-Protocol Label Switching (unicast)
	MPLS_M = 0x8848,		// Multi-Protocol Label Switching (multicast)
	PPPoE_D = 0x8863,		// PPP over Ethernet (Discovery Stage)
	PPPoE_P = 0x8864,		// PPP over Ethernet (PPP Session Stage)
	LWAPP = 0x88BB,			// Light Weight Access Point Protocol
	LLDP = 0x88CC,			// Link Layer Discovery Protocol
	EAPOL = 0x8E88,			// EAP over LAN
	reserved = 0xFFFF		// Reserved
};

enum TRANSPORT_LAYERS
{
//  http://www.networksorcery.com/enp/protocol/ip.htm#Protocol
	HOPOPT = 0,		// IPv6 Hop-by-Hop Option
	ICMP = 1,		// Internet Control Message Protocol
	IGAP = 2,		// IGMP for user Authentication Protocol
	IGMP = 2,		// Internet Group Management Protocol
	RGMP = 2,		// Router-port Group Management Protocol
	GGP = 3,		// Gateway to Gateway Protocol
	IPIP = 4,		// IP in IP encapsulation
	ST = 5,			// Internet Stream Protocol
	TCP = 6,		// Transmission Control Protocol
	UCL = 7,		// CBT
	EGP = 8,		// Exterior Gateway Protocol
	IGRP = 9,		// Interior Gateway Routing Protocol
	BBN = 10,		// BBN RCC Monitoring
	NVP = 11,		// Network Voice Protocol
	PUP = 12,
	ARGUS = 13,
	EMCON = 14,		// Emission Control Protocol
	XNET = 15,		// Cross Net Debugger
	Chaos = 16,
	UDP = 17,		// User Datagram Protocol
	TMux = 18,		// Transport Multiplexing Protocol
	DCN = 19,		// Measurement Subsystems
	HMP = 20,		// Host Monitoring Protocol
	PRM = 21,		// Packet Radio Measurement
	XEROX = 22,		// XEROX NS IDP
	Trunk1 = 23,	// Trunk-1
	Trunk2 = 24,	// Trunk-2
	Leaf1 = 25,		// Leaf-1
	Leaf2 = 26,		// Leaf-2
	RDP = 27,		// Reliable Data Protocol
	IRTP = 28,		// Internet Reliable Transaction Protocol
	ISO = 29,		// ISO Transport Protocol Class 4
	NETBLT = 30,	// Network Block Transfer
	MFE = 31,		// MFE Network Services Protocol
	MERIT = 32,		// MERIT Internodal Protocol
	SEP = 33,		// Sequential Exchange Protocol
	DCCP = 33,		// Datagram Congestion Control Protocol
	TPCP = 34,		// Third Party Connect Protocol
	IDPR = 35,		// Inter-Domain Policy Routing Protocol
	XTP = 36,		// Xpress Transfer Protocol
	DDP = 37,		// Datagram Delivery Protocol
	//IDPR = 38,		// Control Message Transport Protocol
	TP = 39,		// TP++ Transport Protocol
	IL = 40,		// IL Transport Protocol
	IPv6_4 = 41,	// IPv6 over IPv4
	SDRP = 42,		// Source Demand Routing Protocol
	IPv6_rh = 43,	// IPv6 Routing header
	IPv6_fh = 44,	// IPv6 Fragment header
	//IDRP = 45,		// Inter-Domain Routing Protocol
	RSVP = 46,		// Reservation Protocol
	GRE = 47,		// General Routing Encapsulation
	MHRP = 48,		// Mobile Host Routing Protocol
	BNA = 49,		// BNA
	ESP = 50,		// Encapsulating Security Payload
	AH = 51,		// Authentication Header
	INLS = 52,		// Intergrated Net Layer Security TUBA
	IP_e = 53,		// IP with Encryption
	NARP = 54,		// NBMA Address Resolution Protocol
	MEP = 55,		// Minimal Encapsulation Protocol
	TLSP = 56,		// Transport Layer Security Protocol using Kryptonet key management
	SKIP = 57,		// SKIP
	ICMPv6 = 58,	// Internet Control Message Protocol for IPv6
	MLD = 58,		// Multicast Listener Discovery
	IPv6_nnh = 59,	// IPv6 No Next Header
	IPv6_do = 60,	// IPv6 Destination Options
	int_prot = 61,	// Any host internet protocol
	CFTP = 62,		// CFTP
	lan = 63,		// Any local (area?) network
	SATNET = 64,	// SATNET and Backroom EXPAK
	Kryptolan = 65,	// Kryptolan
	RVDP = 66,		// MIT Remote Virtual Disk Protocol
	IPPC = 67,		// Internet Pluribus Packet Core
	file_sys = 68,	// Any distributed file system
	SATNET_M = 69,	// SATNET Monitoring
	VISA = 70,		// VISA Protocol
	IPCU = 71,		// Internet Packet Core Utility
	CPNE = 72,		// Computer Protocol Network Executive
	CPHB = 73,		// Computer Protocol Heart Beat
	WSN = 74,		// Wang Span Network
	PVP = 75,		// Packet Video Protocol
	BSM = 76,		// Backroom SATNET Monitoring
	SUNNDP = 77,	// SUN ND PROTOCOL-Temporary
	WM = 78,		// WIDEBAND Monitoring
	WE = 79,		// WIDEBAND EXPAK
	ISO_IP = 80,	// ISO-IP
	VMTP = 81,		// Versatile Message Transaction Protocol
	SVMTP = 82,		// SECURE-VMTP
	VINES = 83,		// VINES
	TTP = 84,		// TTP
	N_IGP = 85,		// NSFNET-IGP
	DGP = 86,		// Dissimilar Gateway Protocol
	TCF = 87,		// TCF
	EIGRP = 88,		// EIGRP
	OSPF = 89,		// Open Shortest Path First Routing Protocol
	MOSPF = 89,		// Multicast Open Shortest Path First
	SRPCP = 90,		// Sprite RPC Protocol
	LARP = 91,		// Locus Address Resolution Protocol
	MTP = 92,		// Multicast Transport Protocol
	AX25 = 93,		// AX.25
	IP_IPEP = 94,	// IP-within-IP Encapsulation Protocol
	MICP = 95,		// Mobile Internetworking Control Protocol
	EtherIP = 96,	// EtherIP
	EH = 98,		// Encapsulation Header
	PES = 99,		// Any private encryption scheme
	GMTP = 100,		// GMTP
	IFMP = 101,		// Ipsilon Flow Management Protocol
	PNNP = 102,		// PNNI over IP
	PIM = 103,		// Protocol Independent Multicast
	ARIS = 104,		// ARIS
	SCPS = 105,		// SCPS
	QNX = 106,		// QNX
	AN = 107,		// Active Networks
	IPPCP = 108,	// IP Payload Compression Protocol
	SNP = 109,		// Sitara Networks Protocol
	CPP = 110,		// Compaq Peer Protocol
	IPX_IP = 111,	// IPX in IP
	VRRP = 112,		// Virtual Router Redundancy Protocol
	PGM = 113,		// Pragmatic General Multicast
	hop0_p = 114,	// Any 0-hop protocol
	L2TP = 115,		// Level 2 Tunneling Protocol
	DDX = 116,		// D-II Data Exchange
	LATP = 117,		// Interactive Agent Transfer Protocol
	//ST = 118,		// Schedule Transfer
	SRP = 119,		// SpectraLink Radio Protocol
	UTI = 120,		// UTI
	SMP = 121,		// Simple Message Protocol
	SM = 122,		// SM
	PTP = 123,		// Performance Transparency Protocol
	ISI_IPv4 = 124,	// ISIS over IPv4
	FIRE = 125,		// FIRE
	CRTP = 126,		// Combat Radio Transport Protocol
	CRUDP = 127,	// Combat Radio User Datagram
	SSCOPMCE = 128,	// SSCOPMCE
	IPLT = 129,		// IPLT
	SPS = 130,		// Secure Packet Shield
	PIPE = 131,		// Private IP Encapsulation within IP
	SCTP = 132,		// Stream Control Transmission Protocol
	Fibre_c = 133,	// Fibre Channel
	//RSVP = 134,		// RSVP-E2E-IGNORE
	MH = 135,		// Mobility Header
	UDP_Lite = 136,	// Lightweight User Datagram Protocol
	MPLS = 137,		// MPLS in IP
	Reserved = 255	// reserved
};

enum LAYERS
{
//network_transport
	IP4_TCP = 1,
	IP4_UDP = 2,
	IP6_TCP = 3,
	IP6_UDP = 4,
	ARP_ARP = 5,
	ARP_RARP = 6
}; 

#endif