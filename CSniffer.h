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
#ifndef _CSniffer_H_
#define _CSniffer_H_
#include "StdAfx.h"
#include "CDevices.h"
#include "CPacket.h"

class CSniffer : public CDEVICES {
private:
	pcap_t *h_device;				// handle to the open device
	int res;						// errorcode of pcap_next_ex
	struct tm* ltime;				// readable time format
	struct pcap_pkthdr *header;		// packet header
	const u_char *pkt_data;			// packet data

	u_int netmask;					// netmask

	PACKETINFO packet_info;
	CPacket packet;					// packet class instance

	string GetHardwareName(u_short id);
	string GetProtocolName(u_short prot);
	string GetControlBits(u_char ctrl_bits);

public:
	CSniffer();
	virtual ~CSniffer();

	bool SnifPacketsOnDevice(int device);
	bool SendPacketsToDevice(int device);
};

#endif