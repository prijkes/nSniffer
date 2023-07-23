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
#ifndef _CPacket_H_
#define _CPacket_H_
#include "StdAfx.h"

class CPacket
{
private:
	int time_s;
	struct tm* tm_time;	// time structure

public:
	CPacket();
	virtual ~CPacket();

	// variables
	PACKETINFO _packet;

	// functions
	string GetPacketTime(pcap_pkthdr *header);
	string GetMACAddr(MACADDR* mac);
	string GetIP4Addr(IP4ADDR* ip);

	void GetPacketInfo(const u_char* packet, PACKETINFO* const p_info);
	u_short GetChecksum(u_short data_len, u_char* data);
	void FilterPacketData(
		const int start,			// index to start
		const u_int stop,			// index to stop (usually end of packet)
		const u_char* packet,		// pointer to the packet
		string* data,				// pointer to a string to store data in ascii
		string* data_hex			// pointer to a string to store data in hex
	);

	/*
		All u_short's and bigger variable sizes NEED to have their values in network byte,
		so we convert it directly after taken the input.
		u_char variables doens't need to be converted to network byte, why i don't know.
	*/
	ETHERNET_HDR FillETHERNETHDR(u_short network_layer);	// ETHERNET
	IP4_HDR FillIP4HDR(u_short data_len);	// IPv4
	TCP_HDR FillTCPHDR();	// TCP
	ARP_HDR FillARPHDR();	// ARP
	ARP_HDR FillRARPHDR();	// RARP

	IP4ADDR ParseIP4Addr(string ip);
	MACADDR ParseMACAddr(string mac);
};

#endif