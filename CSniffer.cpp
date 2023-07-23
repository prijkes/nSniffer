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
#include "CSniffer.h"


CSniffer::CSniffer()
{
	h_device = 0;
	res = 0;
	ltime = 0;
	header = 0;
	pkt_data = 0;

	netmask = 0xffffffff;
}

CSniffer::~CSniffer()
{
}

bool CSniffer::SnifPacketsOnDevice(int device)
{
	if (!InitializeDevices())
		return false;

	if ((device < 0) || (device > n_devices))
	{
		memset(&errorbuf, 0, sizeof(errorbuf));
		string txt = "Invalid device number";
		strncpy(errorbuf, txt.c_str(), txt.length());
		return false;
	}
	assert(pdevices);
	for (int i=0; i<device; i++)
		pdevices = pdevices->next;

	char* dev_name = GetDeviceName(pdevices->name);
	assert(dev_name);
	h_device = pcap_open(pdevices->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errorbuf);
	if (!h_device)
		return false;

	if (pdevices->addresses)
		netmask = ((sockaddr_in *)pdevices->addresses->netmask)->sin_addr.S_un.S_addr;

	pcap_freealldevs(devices);
	devices = 0;
	if (pcap_datalink(h_device) != DLT_EN10MB)
	{
		string txt = "Only Ethernet network interface cards (NIC) are supported";
		strncpy(errorbuf, txt.c_str(), txt.length());
		return false;
	}

	bpf_program fcode;
	if (pcap_compile(h_device, &fcode, log.packet->filter, 0, netmask) < 0)
	{
		string txt = "Unable to compile filter options, wrong syntax?";
		txt.append("\n");
		txt.append("For filter options see www.winpcap.org/docs/docs31/html/group__language.html");
		strncpy(errorbuf, txt.c_str(), txt.length());
		return false;
	}
	if (pcap_setfilter(h_device, &fcode) < 0)
	{
		string txt = "Unable to set the filter options";
		strncpy(errorbuf, txt.c_str(), txt.length());
		return false;
	}

	cout << "Sniffing on device " << device << " (" << dev_name << ")" << endl;
	cout << "Filter(s): " << (log.packet->filter ? log.packet->filter : "none") << endl << endl;
	delete[] dev_name;	// don't need the buffer with the device name anymore
	dev_name = 0;

	int data_start = 0;
	// main loop
	while((res = pcap_next_ex(h_device, &header, &pkt_data)) >= 0)
	{
		if(res == 0)
			continue;

		memset(&packet_info, 0, sizeof(PACKETINFO));
		packet.GetPacketInfo(pkt_data, &packet_info);
		data_start = 0;
		
		log.Print(2, "Time: %s\n", packet.GetPacketTime(header).c_str());
		log.Print(2, "Length: %i - Caplen: %i\n", header->len, header->caplen);
		log.Print(1, "Layer: ");
		switch (packet_info.ethernet_type)
		{
		case IPv4:
			{
				IP4_HDR* ip = (IP4HDR*)(pkt_data + sizeof(ETHERNET_HDR));
				assert(ip);
				log.Print(1, "IPv4 (%u)\n", packet_info.ethernet_type);
				log.Print(2, "IPv4 Header Checksum: ");
				{
					char* buf = new char[((ip->ver_ihl & 0xF) * 4) + 1];
					assert(buf);
					memcpy(buf, ip, (ip->ver_ihl & 0xF) * 4);
					buf[10] = (u_char)0;	// zero checksum hi byte
					buf[11] = (u_char)0;	// zero checksum low byte
					u_short checked_chksum = packet.GetChecksum(((ip->ver_ihl & 0xF) * 4), (u_char*)buf);
					if (ntohs(ip->hdr_checksum) == checked_chksum)
						log.Print(2, "OK\n");
					else
						log.Print(2, "WRONG (got 0x%x - expected 0x%x)\n", checked_chksum, ntohs(ip->hdr_checksum));

					delete[] buf;
				}
				log.Print(3, "+\t IP Header info\n");
				log.Print(3, "Version: %u\n", ((ip->ver_ihl >> 4)& 0xF));
				log.Print(3, "Header Length: %u bytes\n", (ip->ver_ihl & 0xF) * 4);
				log.Print(3, "TOS: %u\n", ip->tos);
				log.Print(3, "Total Length: %u bytes\n", ntohs(ip->total_len));
				log.Print(3, "Identification: %u\n", ntohs(ip->id));
				log.Print(3, "Flags: %u\n", (ip->flags_fragoffset >> 13));
				log.Print(3, "Fragment Offset: %u\n", (ip->flags_fragoffset & 0x1FFF));
				log.Print(3, "TTL: %u\n", ip->ttl);
				log.Print(1, "Next Header Protocol: ");
				switch ((int)ip->protocol)
				{
				case IGMP:
					{
						IGMP_HDR* igmp = (IGMP_HDR*)(pkt_data + sizeof(ETHERNET_HDR) + sizeof(IP4_HDR));
						assert(igmp);
						log.Print(1, "IGMP (%u)\n", ip->protocol);
						log.Print(2, "Type: %u - Version: %u\n", (igmp->ver_type & 0xF), (igmp->ver_type & 0xF0));
						log.Print(2, "Group address: %u.%u.%u.%u\n", ((igmp->group_addr >> 24) & 0xFF), ((igmp->group_addr >> 16) & 0xFF), 
							((igmp->group_addr >> 8) & 0xFF), (igmp->group_addr & 0xF));
						log.Print(3, "+\t Address Info\n");
						log.Print(1, "Src Info: %s - %s\n", packet.GetIP4Addr(&ip->src_ip).c_str(), packet_info.src_mac.c_str());
						log.Print(1, "Dst Info: %s - %s\n", packet.GetIP4Addr(&ip->dst_ip).c_str(), packet_info.dst_mac.c_str());
					}
					break;
				case TCP:
					{
						TCP_HDR* tcp = (TCP_HDR*)(
							pkt_data + sizeof(ETHERNET_HDR) + ((ip->ver_ihl & 0xF) * 4)
						);
						assert(tcp);
						log.Print(1, "TCP (%u)\n", ip->protocol);
						/*
							Get the total length of the ipv4 header, tcp header and data (ip->total_len).
							Substract the length of the ipv4 header from it, and add the size of the pseudo-ipv4-header.
							Now you have the size of the buffer you need.
							Fill the proper values in the pseudo-ipv4-header, and copy the data with
							the tcp header in the buffer. Then calculate the checksum from of the buffer.
						*/
						log.Print(2, "TCP Header Checksum: ");
						{
							int size = (
								(ntohs(ip->total_len) - ((ip->ver_ihl & 0xF) * 4)) +
								sizeof(pseudo_hdr)
							);
							char* buf = new char[size+1];
							assert(buf);
							char* s = buf;
							// initialize pseudo header
							pseudo_hdr pseudo;
							memcpy(&pseudo.src_ip, &ip->src_ip, 4);
							memcpy(&pseudo.dst_ip, &ip->dst_ip, 4);
							pseudo.protocol = htons((u_short)TCP);
							pseudo.length = htons((u_short)(size - sizeof(pseudo_hdr)));
							// grab the total tcp header size (without data)
							int tcp_size = (tcp->dre >> 4) * 4;
							memcpy(s, tcp, tcp_size);
							s = s + tcp_size;
							memcpy(s,
								(pkt_data + sizeof(ETHERNET_HDR) + ((ip->ver_ihl & 0xF) * 4) + tcp_size),
								size - sizeof(pseudo_hdr) - tcp_size
							);
							s = s + (size - sizeof(pseudo_hdr) - tcp_size);
							memcpy(s, &pseudo, sizeof(pseudo_hdr));
	
							buf[16] = (u_char)0;	// zero checksum hi byte
							buf[17] = (u_char)0;	// zero checksum low byte
							u_short checked_chksum = packet.GetChecksum(size, (u_char*)buf);
							if (ntohs(tcp->checksum) == checked_chksum)
								log.Print(2, "OK\n");
							else
								log.Print(2, "WRONG (got 0x%x - expected 0x%x)\n", checked_chksum, ntohs(tcp->checksum));

							delete[] buf;
						}	// checksum
						log.Print(3, "+\t TCP Header info\n");
						log.Print(3, "Sequence: %u\n",ntohl(tcp->seqno));
						log.Print(3, "Acknowledgement: %u\n", ntohl(tcp->ackno));
						log.Print(3, "Header length: %u bytes\n", ((tcp->dre >> 4) * 4));
						log.Print(2, "Flags: %s\n", GetControlBits(tcp->ctrl_bits).c_str());
						log.Print(3, "Window size: %u\n", tcp->window);
						log.Print(3, "+\t Address Info\n");
						log.Print(1, "Src Info: %s:%u - %s\n", packet.GetIP4Addr(&ip->src_ip).c_str(), ntohs(tcp->src_port), packet_info.src_mac.c_str());
						log.Print(1, "Dst Info: %s:%u - %s\n", packet.GetIP4Addr(&ip->dst_ip).c_str(),  ntohs(tcp->dst_port), packet_info.dst_mac.c_str());

						data_start = (log.packet->keep_headers ? 0 : 
							sizeof(ETHERNET_HDR) +
							((ip->ver_ihl & 0xF) * 4) +
							((tcp->dre >> 4) * 4)
						);
					}	// TCP
					break;
				case UDP:
					{
						UDP_HDR* udp = (UDP_HDR*)(
							pkt_data + sizeof(ETHERNET_HDR) + ((ip->ver_ihl & 0xF) * 4)
						);
						assert(udp);
						log.Print(1, "UDP (%u)\n", ip->protocol);
						log.Print(3, "+\t UDP Header info\n");
						log.Print(2, "CRC: %d\n", udp->crc);
						log.Print(2, "Length: %d bytes\n", udp->len);
						log.Print(1, "Src Info: %s:%u - %s\n", packet.GetIP4Addr(&ip->src_ip).c_str(), ntohs(udp->src_port), packet_info.src_mac.c_str());
						log.Print(1, "Dst Info: %s:%u - %s\n", packet.GetIP4Addr(&ip->dst_ip).c_str(),  ntohs(udp->dst_port), packet_info.dst_mac.c_str());
						data_start = (log.packet->keep_headers ? 0 : 
							sizeof(ETHERNET_HDR) + ((ip->ver_ihl & 0xF) * 4) + sizeof(UDP_HDR)
						);
					}	// UDP
					break;
				default:
					log.Print(1, "unknown (%u not handled yet)\n", ip->protocol);
					log.Print(3, "+\t Address Info\n");
					log.Print(1, "Src Info: %s - %s\n", packet.GetIP4Addr(&ip->src_ip).c_str(), packet_info.src_mac.c_str());
					log.Print(1, "Dst Info: %s - %s\n", packet.GetIP4Addr(&ip->dst_ip).c_str(), packet_info.dst_mac.c_str());
					break;
				}		// transport layers of IPv4
			}	// network layer: IPv4
			break;
		case RARP:
		case ARP:
			{
				ARP_HDR* arp = (ARP_HDR*)(pkt_data+sizeof(ETHERNET_HDR));
				assert(arp);
				switch (packet_info.ethernet_type)
				{
				case RARP:
					log.Print(1, "RARP");
					break;
				case ARP:
					log.Print(1, "ARP");
					break;
				default:
					log.Print(1, "Unknown ARP Type");
					break;
				}
				log.Print(1, " (0x%x)\n", packet_info.ethernet_type);
				log.Print(2, "Hardware type: %s - length: %u\n", GetHardwareName(ntohs(arp->hw_type)).c_str(), arp->hw_len);
				log.Print(2, "Protocol type: %s - length: %u\n", GetProtocolName(ntohs(arp->protocol)).c_str(), arp->prot_len);
				log.Print(1, "Opcode: ");
				int size = sizeof(ARP_Opcodes)/sizeof(s_ARP_Opcodes), x = 0;
				for (x = 1; x < size; x++)
				{
					if (ntohs(arp->opcode) == ARP_Opcodes[x].id)
					{
						log.Print(1, "%u - %s\n", ntohs(arp->opcode), ARP_Opcodes[x].name);
						break;
					}
				}
				if (x == size)
					log.Print(1, "unknown (%u)\n", ntohs(arp->opcode));

				log.Print(1, "ARP Source MAC: %s - IP: %s\n", packet.GetMACAddr(&arp->src_hw).c_str(), packet.GetIP4Addr(&arp->src_ip).c_str());
				log.Print(1, "ARP Dest MAC: %s - IP %s\n", packet.GetMACAddr(&arp->dst_hw).c_str(), packet.GetIP4Addr(&arp->dst_ip).c_str());
				log.Print(3, "Ethernet Source MAC: %s\n", packet_info.src_mac.c_str());
				log.Print(3, "Ethernet Dest MAC: %s\n", packet_info.dst_mac.c_str());
			}			// network layer: ARP
			break;
		default:
			{
				if (packet_info.ethernet_type <= 0x05DC)
					log.Print(1, "IEEE 802.3 Length field (%u)\n", packet_info.ethernet_type);
				else
					log.Print(1, "unknown (0x%x not handled yet)\n", packet_info.ethernet_type);

				log.Print(3, "+\t Address Info\n");
				log.Print(1, "Source MAC: %s\n", packet_info.src_mac.c_str());
				log.Print(1, "Dest MAC: %s\n", packet_info.dst_mac.c_str());
			}
		}				// switch (network_layer)
		packet.FilterPacketData(data_start, header->len, pkt_data, &packet_info.data, &packet_info.data_hex);
		if ((log.packet->show_hex) && (!packet_info.data_hex.empty()))
		{
			log.Print(0, "\nData (in hex):\n%s\n", packet_info.data_hex.c_str());
			packet_info.data_hex.clear();
		}
		if ((log.packet->show_ascii) && (!packet_info.data.empty()))
		{
			log.Print(0, "\nData (in ASCII):\n%s\n", packet_info.data.c_str());
			packet_info.data.clear();
		}

		if (log.packet->delay)
			sleep(log.packet->delay);

		if (log.GetLogLevel() || (log.packet->show_hex && !packet_info.data_hex.empty()) ||
			(log.packet->show_ascii && !packet_info.data.empty()))
		{
			log.Print(0, "-------------------------------------------------------------------------\n\n");
		}
	}
	return true;
}

bool CSniffer::SendPacketsToDevice(int device)
{
	if (!InitializeDevices())
		return false;

	if ((device < 0) || (device > n_devices))
	{
		string txt = "Invalid device number";
		strncpy(errorbuf, txt.c_str(), txt.length());
		return false;
	}

	assert(pdevices);
	for (int i=0; i<device; i++)
		pdevices = pdevices->next;

	h_device = pcap_open(pdevices->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errorbuf);
	if (!h_device)
		return false;

	if (pcap_datalink(h_device) != DLT_EN10MB)
	{
		string txt = "Only Ethernet network interface cards (NIC) are supported";
		strncpy(errorbuf, txt.c_str(), txt.length());
		return false;
	}

	u_short layers;
	u_char packet_buf[MAX_PACKET_SIZE];
	memset(&packet_buf, 0, sizeof(packet_buf));
	u_char* p = packet_buf;

	cout <<		  "    Frame     Network    Transport"	<< endl <<
		IP4_TCP << ": Ethernet    IPv4       TCP"		<< endl << 
		//IP4_UDP << ": Ethernet    IPv4        UDP"		<< endl << 
		//IP6_TCP << ": Ethernet    IPv6        TCP"		<< endl << 
		//IP6_UDP << ": Ethernet    IPv6        UDP"		<< endl <<
		ARP_ARP << ": Ethernet    ARP        ???"		<< endl <<
		ARP_RARP << ": Ethernet    RARP       ???"		<< endl;
	cin >> layers; cout << endl;
	cin.ignore(1, '\n');

	u_int packet_size = 0;
	switch (layers)
	{
	case IP4_TCP:
		{
			cout << "----------------------------" << endl;
			string data;
			cout << "Data to send: ";
			getline(cin, data);
			cout << endl;

			if (data.length() > MAX_PACKET_SIZE)
			{
				stringstream ss;
				ss << "Data too large, max " << MAX_PACKET_SIZE << " bytes allowed";
				string txt;
				txt += ss.str();
				strncpy(errorbuf, txt.c_str(), txt.length());
				return false;
			}

			cout << "-- Transport layer: TCP --" << endl;
			TCP_HDR tcp = packet.FillTCPHDR();
			cout << endl;

			cout << "-- Network layer: IPv4 --" << endl;
			IP4_HDR ip = packet.FillIP4HDR((((tcp.dre >> 4) & 0xF) * 4) + (u_short)data.length());
			cout << endl;

			// checksum = tcp_header + data + pseudo_ipv4_header
			char* buf = new char[ntohs(ip.total_len) - ((ip.ver_ihl & 0xF) * 4) + sizeof(pseudo_hdr) + 1];
			assert(buf);
			char* s = buf;
			pseudo_hdr pseudo;
			memcpy(&pseudo.src_ip, &ip.src_ip, 4);
			memcpy(&pseudo.dst_ip, &ip.dst_ip, 4);
			pseudo.protocol = htons((u_short)TCP);
			pseudo.length = htons((u_short)(ntohs(ip.total_len) - ((ip.ver_ihl & 0xF) * 4)));
			memcpy(s, &tcp, ((tcp.dre >> 4) & 0xF) * 4);
			s = s + (((tcp.dre >> 4) & 0xF) * 4);
			memcpy(s, data.c_str(), data.length());
			s = s + data.length();
			memcpy(s, &pseudo, sizeof(pseudo_hdr));
			tcp.checksum = htons(packet.GetChecksum(ntohs(ip.total_len) - ((ip.ver_ihl & 0xF) * 4) + sizeof(pseudo_hdr), (u_char*)buf));
			//cout << "TCP hdr checksum: " << hex << ntohs(tcp.checksum) << dec << endl;
			delete[] buf;

			cout << "-- Ethernet Header --" << endl;
			ETHERNET_HDR ethernet = packet.FillETHERNETHDR(IPv4);
			cout << endl;

			// ethernet
			memcpy(p, &ethernet.dst_mac, 6);
			p = p+6;
			memcpy(p, &ethernet.src_mac, 6);
			p = p+6;
			*p++ = (ethernet.type & 0xFF);
			*p++ = ((ethernet.type >> 8) & 0xFF);

			// ipv4
			*p++ = ip.ver_ihl;
			*p++ = ip.tos;
			*p++ = (ip.total_len & 0xFF);
			*p++ = ((ip.total_len >> 8) & 0xFF);
			*p++ = (ip.id & 0xFF);
			*p++ = ((ip.id >> 8) & 0xFF);
			*p++ = (ip.flags_fragoffset & 0xFF);
			*p++ = ((ip.flags_fragoffset >> 8) & 0xFF);
			*p++ = ip.ttl;
			*p++ = ip.protocol;
			*p++ = (ip.hdr_checksum & 0xFF);
			*p++ = ((ip.hdr_checksum >> 8) & 0xFF);
			memcpy(p, &ip.src_ip, 4);
			p = p+4;
			memcpy(p, &ip.dst_ip, 4);
			p = p+4;
			if (ip.options_pad)
			{
				*p++ = (ip.options_pad & 0xFF);
				*p++ = ((ip.options_pad >> 8) & 0xFF);
				*p++ = ((ip.options_pad >> 16) & 0xFF);
				*p++ = ((ip.options_pad >> 24) & 0xFF);
			}

			// tcp
			*p++ = (tcp.src_port & 0xFF);
			*p++ = ((tcp.src_port >> 8) & 0xFF);
			*p++ = (tcp.dst_port & 0xFF);
			*p++ = ((tcp.dst_port >> 8) & 0xFF);
			*p++ = (tcp.seqno & 0xFF);
			*p++ = ((tcp.seqno >> 8) & 0xFF);
			*p++ = ((tcp.seqno >> 16) & 0xFF);
			*p++ = ((tcp.seqno >> 24) & 0xFF);
			*p++ = (tcp.ackno & 0xFF);
			*p++ = ((tcp.ackno >> 8) & 0xFF);
			*p++ = ((tcp.ackno >> 16) & 0xFF);
			*p++ = ((tcp.ackno >> 24) & 0xFF);
			*p++ = tcp.dre;
			*p++ = tcp.ctrl_bits;
			*p++ = (tcp.window & 0xFF);
			*p++ = ((tcp.window >> 8) & 0xFF);
			*p++ = (tcp.checksum & 0xFF);
			*p++ = ((tcp.checksum >> 8) & 0xFF);
			*p++ = (tcp.urgent & 0xFF);
			*p++ = ((tcp.urgent >> 8) & 0xFF);
			if (tcp.options_pad)
			{
				*p++ = (tcp.options_pad & 0xFF);
				*p++ = ((tcp.options_pad >> 8) & 0xFF);
				*p++ = ((tcp.options_pad >> 16) & 0xFF);
				*p++ = ((tcp.options_pad >> 24) & 0xFF);
			}
			memcpy(p, data.c_str(), data.length());

			packet_size = (int)(
				sizeof(ETHERNET_HDR) + 
				((ip.ver_ihl & 0xF) * 4) +
				(((tcp.dre  >> 4) & 0xF) * 4)
			);
			packet_size += data.length();

			/*
			// CHECKING PACKET IF IT CONTAINS THE PROPER VALUES AND BYTE ORDER
			// IPv4
				log.Print(2, "IPv4 Header Checksum: ");
				char* bufff = new char[((ip.ver_ihl & 0xF) * 4) + 1];
				assert(bufff);
				char* pp;
				memcpy(bufff, &ip, (ip.ver_ihl & 0xF) * 4);
				bufff[10] = (u_char)0;	// zero checksum hi byte
				bufff[11] = (u_char)0;	// zero checksum low byte
				cout << "IPv4 Header Checksum: ";
				u_short checked_chksum1 = packet.GetChecksum(((ip.ver_ihl & 0xF) * 4), (u_char*)bufff);
				if (ntohs(ip.hdr_checksum) == checked_chksum1)
					log.Print(2, "OK\n");
				else
					log.Print(2, "WRONG (got 0x%x - expected 0x%x)\n"), checked_chksum1, ntohs(ip.hdr_checksum));

				delete[] bufff;
				log.Print(3, "+\t IP Header info\n");
				log.Print(3, "Version: %u\n", ((ip.ver_ihl >> 4)& 0xF));
				log.Print(3, "Header Length: %u bytes\n", (ip.ver_ihl & 0xF) * 4);
				log.Print(3, "TOS: %u\n", ip.tos);
				log.Print(3, "Total Length: %u bytes\n", ntohs(ip.total_len));
				log.Print(3, "Identification: %u\n", ntohs(ip.id));
				log.Print(3, "Flags: %u\n", (ip.flags_fragoffset >> 13));
				log.Print(3, "Fragment Offset: %u\n", (ip.flags_fragoffset & 0x1FFF));
				log.Print(3, "TTL: %u\n", ip->ttl);

			// TCP
				log.Print(2, "TCP Header Checksum: ");
				int size = (
					(ntohs(ip.total_len) - ((ip.ver_ihl & 0xF) * 4)) +
					sizeof(pseudo_hdr)
				);
				char* buff = new char[size+1];
				assert(buff);
				char* ss = buff;
				// initialize pseudo header
				pseudo_hdr pseudos;
				memcpy(&pseudos.src_ip, &ip.src_ip, 4);
				memcpy(&pseudos.dst_ip, &ip.dst_ip, 4);
				pseudos.protocol = htons((u_short)TCP);
				pseudos.length = htons((u_short)(size - sizeof(pseudo_hdr)));
				// grab the total tcp header size (without data)
				int tcp_size = ((tcp.dre >> 4) & 0xF) * 4;
				memcpy(ss, &tcp, tcp_size);
				ss = ss + tcp_size;
				memcpy(ss, data.c_str(),  data.length());
				ss = ss + data.length();
				memcpy(ss, &pseudos, sizeof(pseudo_hdr));
	
				buff[16] = (u_char)0;	// zero checksum hi byte
				buff[17] = (u_char)0;	// zero checksum low byte
				cout << "TCP Header Checksum: ";
				u_short checked_chksum = packet.GetChecksum(size, (u_char*)buff);
				if (ntohs(tcp.checksum) == checked_chksum)
					log.Print(2, "OK");
				else
					log.Print(2, "WRONG (got 0x%x - expected 0x%x)\n", checked_chksum, ntohs(tcp.checksum));

				log.Print(3, "+\t TCP Header info\n");
				log.Print(3, "Sequence: %u\n", ntohs(tcp.seqno));
				log.Print(3, "Acknowledgement: %u\n", ntohs(tcp.ackno));
				log.Print(3, "Header length: %u bytes\n", ((tcp.dre >> 4) * 4));
				log.Print(3, "Flags: %s\n", GetControlBits(tcp.ctrl_bits).c_str());
				log.Print(3, "Window size: %u\n", tcp.window);
				log.Print(3, "+\t Address Info\n");
				log.Print(1, "Src Info: %s:%u - %s\n", packet.GetIP4Addr(&ip.src_ip).c_str(), ntohs(tcp->src_port), packet_info.src_mac.c_str());
				log.Print(1, "Dst Info: %s:%u - %s\n", packet.GetIP4Addr(&ip.dst_ip).c_str(),  ntohs(tcp->dst_port), packet_info.dst_mac.c_str());
				delete[] buff;
			*/
			break;
		}	// case IPv4
	case ARP_ARP:
		{
			cout << "-- ARP Header --" << endl;
			ARP_HDR arp = packet.FillARPHDR();
			cout << endl;
			cout << "-- Ethernet Header --" << endl;
			ETHERNET_HDR ethernet = packet.FillETHERNETHDR(ARP);
			cout << endl;

            memcpy(p, &ethernet.dst_mac, 6);
			p = p+6;
			memcpy(p, &ethernet.src_mac, 6);
			p = p+6;
			*p++ = (ethernet.type & 0xFF);
			*p++ = ((ethernet.type >> 8) & 0xFF);
			*p++ = (arp.hw_type & 0xFF);
			*p++ = ((arp.hw_type >> 8) & 0xFF);
			*p++ = (arp.protocol & 0xFF);
			*p++ = ((arp.protocol >> 8) & 0xFF);
			*p++ = arp.hw_len;
			*p++ = arp.prot_len;
			*p++ = (arp.opcode & 0xFF);
			*p++ = ((arp.opcode >> 8) & 0xFF);
			memcpy(p, &arp.src_hw, 6);
			p = p+6;
			memcpy(p, &arp.src_ip, 4);
			p = p+4;
			memcpy(p, &arp.dst_hw, 6);
			p = p+6;
			memcpy(p, &arp.dst_ip, 4);
			p = p+4;
			if (ntohs(arp.opcode) == 1)
			{
				packet_size = 60;
				for (int x = 0; x < 24; x++)
					*p++ = '\0';
			}
			else
			{
				packet_size = 42;	// look for the comment in the ARP_HDR structure
			}
			break;
		}
	case ARP_RARP:
		{
			cout << "-- RARP Header --" << endl;
			ARP_HDR arp = packet.FillRARPHDR();
			cout << endl;
			cout << "-- Ethernet Header --" << endl;
			ETHERNET_HDR ethernet = packet.FillETHERNETHDR(RARP);
			cout << endl;

            memcpy(p, &ethernet.dst_mac, 6);
			p = p+6;
			memcpy(p, &ethernet.src_mac, 6);
			p = p+6;
			*p++ = (ethernet.type & 0xFF);
			*p++ = ((ethernet.type >> 8) & 0xFF);
			*p++ = (arp.hw_type & 0xFF);
			*p++ = ((arp.hw_type >> 8) & 0xFF);
			*p++ = (arp.protocol & 0xFF);
			*p++ = ((arp.protocol >> 8) & 0xFF);
			*p++ = arp.hw_len;
			*p++ = arp.prot_len;
			*p++ = (arp.opcode & 0xFF);
			*p++ = ((arp.opcode >> 8) & 0xFF);
			memcpy(p, &arp.src_hw, 6);
			p = p+6;
			memcpy(p, &arp.src_ip, 4);
			p = p+4;
			memcpy(p, &arp.dst_hw, 6);
			p = p+6;
			memcpy(p, &arp.dst_ip, 4);
			p = p+4;
			if (ntohs(arp.opcode) == 3)
			{
				packet_size = 60;
				for (int x = 0; x < 24; x++)
					*p++ = '\0';
			}
			else
			{
				packet_size = 42;	// look for the comment in the ARP_HDR structure
			}
			break;
		}
	default:
		{
			string txt = "Invalid number";
			strncpy(errorbuf, txt.c_str(), txt.length());
			return false;
			break;
		}
	}	// switch (layer)

	string data_hex;
	string dat;
	packet.FilterPacketData(0, packet_size, packet_buf, &dat, &data_hex);
	cout << "Your created packet" << endl << data_hex << endl;
	cout << endl << "Sending the packet...";
	if (pcap_sendpacket(h_device, packet_buf, packet_size) == -1)
		cout << " failed" << endl;
	else
		cout << " done" << endl;

	return true;
}

string CSniffer::GetHardwareName(u_short id)
{
	// 0 or less is invalid, and 33+ are invalid (check the struct).
	// Hardware type id's are Ascending (1, 2, 3, etc.)
	stringstream ss;
	string str;
	for (int x = 0; x < sizeof(HardwareTypes)/sizeof(s_HardwareTypes); x++)
	{
		if (HardwareTypes[x].hw_type == id)
		{
			switch (log.GetLogLevel())
			{
			case 1:
				ss << HardwareTypes[x].hw_name;
				break;
			case 2:
				ss << HardwareTypes[x].hw_name;
				break;
			case 3:
				ss << HardwareTypes[x].hw_name << " (" << HardwareTypes[x].reference << ")";
				break;
			}
			break;
		}
	}
	if (ss.str() == "")
		ss << "unknown (" << id << ")";

	str += ss.str();
	return str;
}

string CSniffer::GetProtocolName(u_short prot)
{
	stringstream ss("");
	string str;
	for (int x = 0; x < sizeof(NetworkLayers)/sizeof(s_NetworkLayers); x++)
	{
		if (NetworkLayers[x].id == prot)
		{
			switch (log.GetLogLevel())
			{
			case 1:
				ss << NetworkLayers[x].short_name;
				break;
			case 2:
				ss << NetworkLayers[x].long_name;
				break;
			case 3:
				ss << NetworkLayers[x].long_name << " (" << NetworkLayers[x].short_name << ")";
				break;
			}
			break;
		}
	}
	if (ss.str() == "")
		ss << "unknown (" << prot << ")";

	str += ss.str();
	return str;
}

string CSniffer::GetControlBits(u_char ctrl_bits)
{
	stringstream ss("|");
	string str;
	if (ctrl_bits & URG_BIT)
		ss << "URG|";
	if (ctrl_bits & ACK_BIT)
		ss << "ACK|";
	if (ctrl_bits & PSH_BIT)
		ss << "PSH|";
	if (ctrl_bits & RST_BIT)
		ss << "RST|";
	if (ctrl_bits & SYN_BIT)
		ss << "SYN|";
	if (ctrl_bits & FIN_BIT)
		ss << "FIN|";

	ss << " (" << (u_short)ctrl_bits << ")";
	str += ss.str();
	return str;
}