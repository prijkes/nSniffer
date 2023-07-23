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
#ifndef _CLog_
#define _CLog_
#include "StdAfx.h"
#include <string>

typedef struct s_packet
{
	// Packet log info
	int         delay;			// Delay between the packets to show
	bool		show_ascii;		// Show packet data in ASCII
	bool		show_hex;		// Show packet data in hex with ASCII
	char*       filter;			// filter option
	bool		keep_headers;	// Show the full packet data (headers + data)
} s_packet;


class CLog
{
private:
	stringstream ss;
	string log_buffer;
	u_short log_level;

public:
	CLog();
	virtual ~CLog();

	// variables
	s_packet* packet;	// pointer (->) looks nicer then a dot (.)

	// functions
	string GetError();
	void SetLogLevel(u_short level);
	u_short GetLogLevel();
	bool Print(u_short log_level_required, char* str, ...);
};

#endif