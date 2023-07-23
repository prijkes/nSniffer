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
#ifndef _StdAfx_H_
#define _StdAfx_H_
#define HAVE_REMOTE 

 // both
#include <cstdio>
#include <cassert>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <fstream>
#include <string>
using namespace std;

#include <pcap.h>
#include "NetworkStructs.h"
 #ifdef _WIN32
// WINDHOOS
	#define WIN32_MEAND_AND_LEAN
	#define WPCAP
	#include <winsock2.h>
	#include <windows.h>
	#if (_compiler == MSVC)
		#pragma comment(lib, "ws2_32")		// sockets stuff
		#pragma comment(lib, "Iphlpapi")	// GetAdaptersInfo
		#pragma comment(lib, "wpcap")		// winpcap
		#pragma comment(lib, "packet")		// winpcap
		#pragma warning(disable : 4267)	// size_t to u_int warning
		#pragma warning(disable : 4244)	// time_t to u_int warning
	#endif
	#define sleep(n) Sleep(n)
#else
// LINUX
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <stdlib.h>
	#include <arpa/inet.h>
	#include <netinet/ip.h>
	#include <netinet/tcp.h>
	#include <errno.h>
	#include <unistd.h>
#endif

#define MAX_PACKET_SIZE 65535		// max size a packet can be
#define HAVE_ADMIN_ACCESS 0			// to log the current time you need to have access to
									// the clock, which i didn't had on my work :P

typedef struct PACKETINFO
{
	string src_mac, dst_mac;
	u_short ethernet_type;
	string data, data_hex;
} PACKETINFO;

#endif	// ifndef _StdAfx_H_