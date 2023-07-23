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
#include "CLog.h"

CLog::CLog()
{
	packet = 0;
	log_level = 0;
	log_buffer.clear();

	packet = new s_packet;
	assert(packet);
	memset(packet, 0, sizeof(s_packet));
}

CLog::~CLog()
{
	if (packet)
		delete packet;

	packet = 0;
}

void CLog::SetLogLevel(u_short level)
{
	log_level = level;
}

u_short CLog::GetLogLevel()
{
	return log_level;
}

bool CLog::Print(u_short log_level_required, char* str, ...)
{
	if (log_level < log_level_required)
		return false;

	va_list list;
	va_start(list, str);
	vprintf(str, list);
	va_end(list);
	fflush(0);
	return true;
}

string CLog::GetError()
{
	void* MsgBuf;
	string ErrorMsg;
	u_long LastError = GetLastError();

	if (!FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		0, LastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&MsgBuf, 0, 0)
		)
		return false;

	ErrorMsg = (char*)MsgBuf;
	return ErrorMsg;
}
