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
#include "CPacket.h"

CPacket::CPacket()
{
	tm_time = 0;
}

CPacket::~CPacket()
{
}

std::string CPacket::GetPacketTime(pcap_pkthdr *header)
{
	assert(header);

	stringstream ss("");
	tm_time = localtime((time_t*)&header->ts);
	ss << tm_time->tm_hour << ":" << tm_time->tm_min << ":" << tm_time->tm_sec << ".";
	ss << header->ts.tv_usec;
	return ss.str();
}

void CPacket::GetPacketInfo(const u_char* packet, PACKETINFO* const p_info)
{
	assert(packet);
	assert(p_info);

	ETHERNET_HDR* ethernet = (ETHERNET_HDR*)(packet);
	assert(ethernet);

	p_info->dst_mac = GetMACAddr(&ethernet->dst_mac);
	p_info->src_mac = GetMACAddr(&ethernet->src_mac);
	p_info->ethernet_type = ntohs(ethernet->type);
}

void CPacket::FilterPacketData(const int start, const u_int stop, const u_char* packet, string* data, string* data_hex)
{
	assert(packet);
	assert(data);
	assert(data_hex);

	string line;
	line.clear();
	stringstream ss;
	int x=0, y=0;
	if ((u_int)start >= stop)
		return;

	for (u_int i = start; i < stop; i++)
	{
		ss << setw(2) << right << setfill('0') << hex << (int)packet[i] << " ";
		if ((int)packet[i] < 33 || (int)packet[i] > 126)		// non-printable character
		{
			switch ((int)packet[i])
			{
			case 0:								// (hex)00 - (dec)0 = string terminator
			case 10:							// (hex)0a - (dec)10 = new line
				line += '.';
				*data += '\n';
				break;
			case 13:							// (hex)0d - (dec)13 = carriage return
				line += '.';
				*data += '\r';
				break;
			case 32:							// (hex)20 - (dec)32 = space
				line += ' ';
				*data += ' ';
				break;
			default:
				line += '.';
				*data += '.';
				break;
			}
		}
		else													// ascii char
		{
			line += packet[i];
			*data += packet[i];
		}

		x++;													// one hex block (0xFF = 1 byte)
		if (x == 8)
			ss << "    ";

		if (x > 15)
		{
			ss << "    ";
			line += '\n';
			ss << line;
			x = 0;
			y = 0;
			*data_hex += ss.str();
			ss.str("");
			line.clear();
		}
	}

	if (x != 0)
	{
		x *= 3;
		x += (x > 23) ? 4 : 0;
		int count = 56 - x;
		for (int a = 0; a < count; a++)
			ss << ' ';

		ss << line;
	}
	*data_hex += ss.str();
}

MACADDR CPacket::ParseMACAddr(string str)
{
	bool index = 0;
	char number = 0, total_number = 0;
	u_char mac_index = 0;
	MACADDR mac;
	for (string::iterator it = str.begin(); it != str.end(); ++it)
	{
		if ((*it == ':') || (*it == '-'))
		{
			switch (mac_index++)
			{
			case 0:
				mac.byte0 = total_number;
				break;
			case 1:
				mac.byte1 = total_number;
				break;
			case 2:
				mac.byte2 = total_number;
				break;
			case 3:
				mac.byte3 = total_number;
				break;
			case 4:
				mac.byte4 = total_number;
				break;
			}
			total_number = 0;
			index = 0;
			continue;
		}
		number = 0;
		switch ((int)*it)
		{
		case 0:
		case 48:
			number = 0;
			break;
		case 1:
		case 49:
			number = 1;
			break;
		case 2:
		case 50:
			number = 2;
			break;
		case 3:
		case 51:
			number = 3;
			break;
		case 4:
		case 52:
			number = 4;
		case 5:
		case 53:
			number = 5;
			break;
		case 6:
		case 54:
			number = 6;
			break;
		case 7:
		case 55:
			number = 7;
			break;
		case 8:
		case 56:
			number = 8;
			break;
		case 9:
		case 57:
			number = 9;
			break;
		case 10:
		case 65:	// 'A'
		case 97:	// 'a'
			number = 10;
			break;
		case 11:
		case 66:
		case 98:
			number = 11;
			break;
		case 12:
		case 67:
		case 99:
			number = 12;
			break;
		case 13:
		case 68:
		case 100:
			number = 13;
			break;
		case 14:
		case 69:
		case 101:
			number = 14;
			break;
		case 15:
		case 70:	// 'F'
		case 102:	// 'f'
			number = 15;
			break;
		default:
			cout << "Fatal error: invalid hex char found (" << *it << ")" << endl;
			exit(1);
		}
		if (!index)
			total_number = (16 * number);
		else
			total_number += number;

		index = 1;
	}
	mac.byte5 = total_number;
	return mac;
}

string CPacket::GetMACAddr(MACADDR* mac)
{
	assert(mac);

	string str_mac;
	char char_mac[20+1];
	memset(char_mac, 0, sizeof(char_mac));
	sprintf(char_mac, "%02X:%02X:%02X:%02X:%02X:%02X", 
		mac->byte0, mac->byte1, mac->byte2, mac->byte3, mac->byte4, mac->byte5);

	str_mac = char_mac;
	return str_mac;
}

IP4ADDR CPacket::ParseIP4Addr(string str)
{
	u_char index = 0;
	string addr;
	IP4ADDR ip;
	for (string::iterator it = str.begin(); it != str.end(); ++it)
	{
		if (*it == '.')
		{
			switch (index++)
			{
			case 0:
				ip.addr1 = (char)atoi(addr.c_str());
				break;
			case 1:
				ip.addr2 = (char)atoi(addr.c_str());
				break;
			case 2:
				ip.addr3 = (char)atoi(addr.c_str());
				break;
			}
			addr.clear();
			continue;
		}
		addr += *it;
	}
	ip.addr4 = (char)atoi(addr.c_str());
	return ip;
}

string CPacket::GetIP4Addr(IP4ADDR* ip)
{
	assert(ip);

	string str_ip;
	stringstream ss;
	ss << (int)ip->addr1 << "." << (int)ip->addr2 << "." << (int)ip->addr3 << "." << (int)ip->addr4;
	ss >> str_ip;
	return str_ip;
}

u_short CPacket::GetChecksum(u_short data_len, u_char* data_buff)
{
//  http://www.geocities.com/SiliconValley/2072/rawsock.htm
//  explains how the checksum calculation works
	u_short word16 = 0;
	u_int sum = 0;
	u_short i;
    
	// make 16 bit out of every two 8 bit
	// and add them to the 32bit
	for (i = 0; i < data_len; i += 2)
	{
		word16 = 0;
		word16 = ((data_buff[i] << 8) & 0xFF00) + (data_buff[i+1] & 0xFF);
		//cout << i << ": " << hex << word16 << dec << endl;

		sum += (u_short)word16;	
	}

	// max length is 4 hex chars
	// add everything after the 4 chars to it
	// ie. 1FCE5 becomes FCE5 + 1
	// 1 hex char = 4 bits, total of 16 bits
	while (sum >> 16)
	  sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement the result
	sum = ~sum;

	return ((u_short)sum);
}

ETHERNET_HDR CPacket::FillETHERNETHDR(u_short network_layer)
{
	ETHERNET_HDR ethernet;
	memset(&ethernet, 0, sizeof(ETHERNET_HDR));

	string str;
	cout << "Dest MAC Address (in hex): "; cin >> str;
	ethernet.dst_mac = ParseMACAddr(str);
	str.clear();
	cout << "Source MAC Address (in hex): "; cin >> str;
	ethernet.src_mac = ParseMACAddr(str);

	ethernet.type = htons(network_layer);
	return ethernet;
}

IP4_HDR CPacket::FillIP4HDR(u_short data_len)
{
	IP4_HDR ip;
	memset(&ip, 0, sizeof(IP4HDR));
	string buf;
	//cout << "Use optional options? "; cin >> ip.options_pad; ip.options_pad = htonl(ip.options_pad);

	cout << "Dest IP Address: "; cin >> buf;
	ip.dst_ip = ParseIP4Addr(buf);
	buf.clear();
	cout << "Source IP Address: "; cin >> buf;
	ip.src_ip = ParseIP4Addr(buf);
	buf.clear();

	ip.protocol = TCP;
	ip.ttl = 128;
	ip.flags_fragoffset = htons(16384);

	cout << "Identification number: "; cin >> ip.id; ip.id = htons(ip.id);
	u_short hdr_len = sizeof(IP4_HDR) - (ip.options_pad ? 0 : 4);
	ip.total_len = htons((data_len + hdr_len));
	ip.tos = 0;
	{
		u_char version = 4;							// 0000 0100
		version <<= 4;								// 0100 0000 = 64
		u_char length = (char)(hdr_len / 4);		// 0000 0101 = 5 (or 0000 0110 = 6 with options set)
													// --------- +
		ip.ver_ihl = (version | length);			// 0100 0101 = 69
	}

	ip.hdr_checksum = htons(GetChecksum(hdr_len, (u_char*)&ip));
	return ip;
}

TCP_HDR CPacket::FillTCPHDR()
{
	TCP_HDR tcp;
	memset(&tcp, 0, sizeof(TCP_HDR));
	cout << "Source port: "; cin >> tcp.src_port; tcp.src_port = htons(tcp.src_port);
	cout << "Dest port: "; cin >> tcp.dst_port; tcp.dst_port = htons(tcp.dst_port);
	cout << "Sequence number: "; cin >> tcp.seqno; tcp.seqno = htonl(tcp.seqno);
	//srand(time(0)); tcp.seqno = rand();
	cout << "Acknowledgement number (use 0 with SYN): "; cin >> tcp.ackno; tcp.ackno = htonl(tcp.ackno);
	//tcp.ackno = htons(0);
	//cout << "Options (optional)? "; cin >> tcp.options_pad; tcp.options_pad = htonl(tcp.options_pad);
	{
		u_int length = (sizeof(TCP_HDR) - (tcp.options_pad ? 0 : 4)) / 4;
		tcp.dre = (length << 4);
		u_char options = (u_char)0;		// 0000 0000
		bool buf;
		//cout << "URG bit: "; cin >> buf;
		//options |= (buf << 5);			// 00.0 0000
		if (tcp.ackno)
		{
			cout << "ACK bit: "; cin >> buf;
			options |= (buf << 4);		// 000. 0000
		}
		cout << "PSH bit: "; cin >> buf;
		options |= (buf << 3);			// 0000 .000
		cout << "RST bit: "; cin >> buf;
		options |= (buf << 2);			// 0000 0.00
		cout << "SYN bit: "; cin >> buf;
		options |= (buf << 1);			// 0000 00.0
		cout << "FIN bit: "; cin >> buf;
		options |= (buf << 0) ;			// 0000 000.
		tcp.ctrl_bits = options;
		cout << "Options: " << (u_int)options <<endl;
	}
	tcp.window = htons((u_short)MAX_PACKET_SIZE);
	// if (tcp.ctrl_bits & URG_BIT)
	//	tcp.urgent = htons(1);
	//cout << "Urgent pointer? "; cin >> tcp.urgent; tcp.urgent = htons(tcp.urgent);

	return tcp;
}

ARP_HDR CPacket::FillARPHDR()
{
	ARP_HDR arp;
	// 0 or less is invalid, and 33+ is invalid.
	// Hardware type id's are Ascending (1, 2, 3, ..)
	arp.hw_type = htons(HardwareTypes[1].hw_type);
	arp.hw_len = HardwareTypes[1].hw_len;
	arp.protocol = htons((u_short)IPv4);
	arp.prot_len = 4;

	cout << "Opcode (1 Request - 2 Reply): "; cin >> arp.opcode;
	int size = sizeof(ARP_Opcodes)/sizeof(s_ARP_Opcodes);
	if ((arp.opcode != 1) && (arp.opcode != 2))
	{
		cout << "Fatal error: Invalid ARP opcode (" << arp.opcode << ")" << endl;
		exit(1);
	}
	arp.opcode = htons(arp.opcode);

	// -- NOTE about arp / rarp
	// Opcode 1 is a request. Request frames are always 60 bytes long, but because an ARP header (28)
	// + an ETHERNET header (14) is not 60 but 42, it is appended with 18 bytes of zero's to to make
	// up the 60 bytes size. Also, the destination hardware address is always 0, since its not known.
	// Opcode 2 is a reply. Reply frames are usually 42 (28 + 14) bytes long, and don't need
	// to be appened with zero's to make up 60 bytes.
	string str;
	cout << "Source MAC (in hex): "; cin >> str;
	arp.src_hw = ParseMACAddr(str);
	str.clear();
//
	cout << "Dest MAC (in hex): "; cin >> str;
	arp.dst_hw = ParseMACAddr(str);
	str.clear();
//
	cout << "Source IPv4: "; cin >> str;
	arp.src_ip = ParseIP4Addr(str);
	str.clear();
	cout << "Dest IPv4: "; cin >> str;
	arp.dst_ip = ParseIP4Addr(str);
	str.clear();
	return arp;
}

ARP_HDR CPacket::FillRARPHDR()
{
	ARP_HDR rarp;
	// Hardware type id's are Ascending (1, 2, 3, ..)
	// 0 or less is invalid, and 33+ is invalid.
	rarp.hw_type = htons(HardwareTypes[1].hw_type);
	rarp.hw_len = HardwareTypes[1].hw_len;
	rarp.protocol = htons((u_short)IPv4);
	rarp.prot_len = 4;

	cout << "Opcode (use 0 for a list): "; cin >> rarp.opcode;
	int size = sizeof(ARP_Opcodes)/sizeof(s_ARP_Opcodes);
	if (!rarp.opcode)
	{
		for (int x = 1; x < size; x++)
			cout << "Opcode " << x << " - " << ARP_Opcodes[x].name << endl;

		cout << "Opcode: "; cin >> rarp.opcode;
	}
	if (rarp.opcode > size || rarp.opcode <= 0 || (rarp.opcode != 3 && rarp.opcode != 4))
	{
		cout << "Fatal error: Invalid RARP opcode (" << rarp.opcode << ")" << endl;
		exit(1);
	}
	rarp.opcode = htons(rarp.opcode);

	string str;
	cout << "Source MAC (in hex): "; cin >> str;
	rarp.src_hw = ParseMACAddr(str);
	str.clear();
	cout << "Dest MAC (in hex): "; cin >> str;
	rarp.dst_hw = ParseMACAddr(str);
	str.clear();
	cout << "Source IPv4: "; cin >> str;
	rarp.src_ip = ParseIP4Addr(str);
	str.clear();
//
	cout << "Dest IPv4: "; cin >> str;
	rarp.dst_ip = ParseIP4Addr(str);
	str.clear();
//
	return rarp;
}