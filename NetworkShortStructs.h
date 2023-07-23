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
#ifndef _NetworkShortStructs_h_
#define _NetworkShortStructs_h_
// TCP Flags
// first 2 bits are the 2 bits remaining from the 6-bit reserved field
// 0-3: data offset
// 4-9: reserved
// 10-15: control bit
//
// 0-7: data offset (4) + reserved (4)
// 8-15: reserved (2) + control bits (6)
#define URG_BIT 32 // 00100000
#define ACK_BIT 16 // 00010000
#define PSH_BIT 8  // 00001000
#define RST_BIT 4  // 00000100
#define SYN_BIT 2  // 00000010
#define FIN_BIT 1  // 00000001

// Network layer short structs
// all numbers are BITS
typedef struct MACADDR
{
	u_char byte0;	// 00 (4+4 = 8)
	u_char byte1;	// 11 (4+4 = 8)
	u_char byte2;	// 22 (4+4 = 8)
	u_char byte3;	// 33 (4+4 = 8)
	u_char byte4;	// 44 (4+4 = 8)
	u_char byte5;	// 55 (4+4 = 8)
					//	-------- +
					//		48/8 = 6 bytes
} MACADDR;

typedef struct IP4ADDR
{
	u_char		addr1;			// 1.*.*.* (8)
	u_char		addr2;			// 255.2.*.* (C class) (8)
	u_char		addr3;			// 255.255.3.* (B class) (8)
	u_char		addr4;			// 255.255.255.4 (A class) (8)
								//	-------- +
								//		32/8 = 4 bytes
} IP4ADDR;

// Pseudo header to calculate TCP checksum
typedef struct pseudo_hdr
{
	u_int src_ip;
	u_int dst_ip;
	u_short protocol;
	u_short length;
} pseudo_hdr;

#endif
