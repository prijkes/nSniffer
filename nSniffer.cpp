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
#include "nSniffer.h"

void Help()
{
	cout << "      Usage: <log options> <options> <param> "						<< endl;
	cout << "                                             "						<< endl;
	cout << "    Log Options              Descr           "						<< endl;
	cout << "   ---------------------    -------          "						<< endl;
	cout << "     -v                       Least verbose"						<< endl;
	cout << "     -vv                      More verbose"						<< endl;
	cout << "     -vvv                     Full verbose, shows all info"        << endl;
	cout << "     -pd <d>                  Packets delay (in ms), default 200"	<< endl;
	cout << "     -o                       Show packets in ascii"				<< endl;
	cout << "     -oh                      Show packets in hexadecimal"			<< endl;
	cout << "     -ph                      Leave packet headers in the output"	<< endl;
	cout << "                                             "						<< endl;
	cout << "    Options                  Descr           "						<< endl;
	cout << "   ---------                -------          "						<< endl;
	cout << "      -pl                     List all network devices (WinPCap)"		<< endl;
	cout << "      -wl                     List all network devices info (Windows)" << endl;
	cout << "      -i <n>                  Show advanced info of device <n>"	<< endl;
	cout << "      -f <filter>             Filter to use/compile, use quotes"	<< endl;
	cout << "      -snif <n>               Start to snif on device <n>"			<< endl;
	cout << "      -send <n>               Send a custom packet to device <n>"	<< endl;
	cout << "                                             "	;//					<< endl;
}

int main(int argc, char *argv[])
{
	cout << "                                      " << endl;
	cout << "             nSniffer                 " << endl;
	cout << "                                      " << endl;
	if (argc < 2)
	{
		Help();
		return 1;
	}
	cout << "--------------------------------------" << endl;
	CSniffer sniffer;
	for (int i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-pl") == 0)
		{
			if (!sniffer.ShowAllDevices())
				sniffer.ShowLastError();

			break;
		}
		else if (strcmp(argv[i], "-wl") == 0)
		{
			if (!sniffer.ShowAllDevicesInfo())
				sniffer.ShowLastError();

			break;
		}
		else if (strcmp(argv[i], "-i") == 0)
		{
			if (!argv[++i])
			{
				Help();
				return 1;
			}

			if (!sniffer.ShowDeviceInformation(atoi(argv[i])))
				sniffer.ShowLastError();

		}
		else if (strcmp(argv[i], "-snif") == 0)
		{
			if (!argv[++i])
			{
				Help();
				return 1;
			}
			if (!sniffer.SnifPacketsOnDevice(atoi(argv[i])))
				sniffer.ShowLastError();

			++i;
		}
		else if (strcmp(argv[i], "-send") == 0)
		{
			if (!argv[++i])
			{
				Help();
				return 1;
			}
			if (!sniffer.SendPacketsToDevice(atoi(argv[i])))
				sniffer.ShowLastError();

			i++;
		}
		else if (strcmp(argv[i], "-f") == 0)
			sniffer.log.packet->filter = argv[++i];
		else if (strcmp(argv[i], "-v") == 0)
			sniffer.log.SetLogLevel(1);
		else if (strcmp(argv[i], "-vv") == 0)
			sniffer.log.SetLogLevel(2);
		else if (strcmp(argv[i], "-vvv") == 0)
			sniffer.log.SetLogLevel(3);
		else if (strcmp(argv[i], "-pd") == 0)
			sniffer.log.packet->delay = atoi(argv[++i]);
		else if (strcmp(argv[i], "-o") == 0)
			sniffer.log.packet->show_ascii = true;
		else if (strcmp(argv[i], "-oh") == 0)
			sniffer.log.packet->show_hex = true;
		else if (strcmp(argv[i], "-ph") == 0)
			sniffer.log.packet->keep_headers = true;
		else
		{
			Help();
			break;
		}
	}
	return 0;
}