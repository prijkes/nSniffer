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
#include "CDevices.h"

CDEVICES::CDEVICES()
{
	devices = 0;			// point it to nothing
	pdevices = 0;			// point it to nothing
	n_devices = 0;			// number of devices found, nothing yet

	memset(&errorbuf, 0, sizeof(errorbuf));
	log.packet->delay = 200;
}

CDEVICES::~CDEVICES()
{
	if (devices)					// if devices points to a list of devices
	{
		pcap_freealldevs(devices);	// free it
		devices = 0;
	}
}

bool CDEVICES::InitializeDevices()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 0, &devices, errorbuf) == -1)
		return false;

	pdevices = devices;		// point it to devices[0]
	assert(devices);

	do {
		n_devices++;		// count the devices
	} while (pdevices = pdevices->next);

    n_devices -= 1;			// 2('3') - 1 = 1('2') (0 and 1 = 2)
	pdevices = devices;		// point it back to the first device
	return true;
}

void CDEVICES::ShowLastError()
{
	cout << errorbuf << endl;
}

bool CDEVICES::ShowAllDevices()
{
	if (!InitializeDevices())
		return false;

	if ((!devices) || (!pdevices))
		return false;

	else
	{
		int i = 0;
		do {
			char* device_name = GetDeviceName(pdevices->name);
			assert(device_name);
			cout << i++ << ": " << device_name << endl << "   ";
			delete[] device_name;
			device_name = 0;

			if (pdevices->description)
				cout << pdevices->description;
			else
				cout << "no description found";

			cout << endl << endl;
			n_devices++;
		} while (pdevices = pdevices->next);
	}
	pdevices = devices;
	return true;
}

bool CDEVICES::ShowDeviceInformation(int device)
{
	if (!InitializeDevices())
		return false;

	if ((device < 0) || (device > n_devices))
	{
		strncpy(errorbuf, "Invalid device number", 21);
		return false;
	}

	for (int x = 0; x < device; x++)
		pdevices = pdevices->next;

	char* device_name = GetDeviceName(pdevices->name);
	assert(device_name);
	cout << "Device name: " << device_name << endl;
	delete[] device_name;
	cout << "Device description: " << 
		((pdevices->description) ? pdevices->description : "not availlable") << endl;
	cout << "Loopback address: " << 
		((pdevices->flags & PCAP_IF_LOOPBACK) ? "yes" : "no") << endl;

	int addr = 0;
	for (device_addr = pdevices->addresses; device_addr; device_addr = device_addr->next, addr++)
	{
		cout << endl << "-- Device address #" << addr << endl;
		cout << "Address Family Name: ";
		switch (device_addr->addr->sa_family)
		{
			case AF_INET:
				cout << "AF_INET (0x" << hex << device_addr->addr->sa_family << " - IPv4)" << endl;
				if (device_addr->addr)
					cout << "IP address: "	<< inet_ntoa(((sockaddr_in *)device_addr->addr)->sin_addr) << endl;
				if (device_addr->netmask)
					cout << "Netmask address: " << inet_ntoa(((sockaddr_in *)device_addr->netmask)->sin_addr) << endl;
				if (device_addr->broadaddr)
					cout << "Broadcast address: " << inet_ntoa(((sockaddr_in *)device_addr->broadaddr)->sin_addr) << endl;
				if (device_addr->dstaddr)
					cout << "Destination address: " << inet_ntoa(((sockaddr_in *)device_addr->dstaddr)->sin_addr) << endl;
				break;
				
			case AF_INET6:
			{
				cout << "AF_INET6 (0x" << hex << device_addr->addr->sa_family << " - IPv6)" << endl;
				cout << "IP address: ";
				char* ip = new char[128+1];
				assert(ip);

				#ifdef WIN32
					sockaddrlen = sizeof(sockaddr_in6);
				#else
					sockaddrlen = sizeof(sockaddr_storage);
				#endif
				if (getnameinfo(device_addr->addr, sockaddrlen, ip, 128, NULL, 0, NI_NUMERICHOST) != 0)
					cout << ip << endl;
				else
					cout << " unknown" << endl;

				delete[] ip;
			}
				
			default:
				cout << " Other (no info)" << endl;
				break;
		}
	}
	pdevices = devices;
	return true;
}

bool CDEVICES::SnifPacketsOnDevice(int device)
{
	return false;
}

bool CDEVICES::SendPacketsToDevice(int device)
{
	return false;
}

bool CDEVICES::ShowAllDevicesInfo()
{
	IP_ADAPTER_INFO* adapts = new IP_ADAPTER_INFO;
	assert(adapts);
	IP_ADAPTER_INFO* adapters = adapts;

	u_long size = sizeof(IP_ADAPTER_INFO);
	int error;

	error = GetAdaptersInfo(adapts, &size);
	if (error == ERROR_BUFFER_OVERFLOW)
	{
		delete adapts;
		// make the buffer big enough
		adapts = new IP_ADAPTER_INFO[size];
	}
	// try again
	error = GetAdaptersInfo(adapts, &size);
	if (error != ERROR_SUCCESS)
	{
		switch (error)
		{
		case ERROR_BUFFER_OVERFLOW:
			strcpy(errorbuf, "GetAdaptersInfo() failed: Buffer size too small");
			break;
		case ERROR_INVALID_DATA:
			strcpy(errorbuf, "GetAdaptersInfo() failed: Invalid adapter information retrieved");
			break;
		case ERROR_INVALID_PARAMETER:
			strcpy(errorbuf, "GetAdaptersInfo() failed: One of the given parameters is invalid");
			break;
		case ERROR_NO_DATA:
			strcpy(errorbuf, "GetAdaptersInfo() failed: No adapter information exists for the local computer");
			break;
		case ERROR_NOT_SUPPORTED:
			strcpy(errorbuf, "GetAdaptersInfo() failed: GetAdaptersInfo() is not supported");
			break;
		default:
			strcpy(errorbuf, log.GetError().c_str());
			break;
		}
		delete adapts;
		adapts = 0;
		return false;
	}

	IP_ADDR_STRING* ipaddr_p;
	int n = 0;
	for (int x = 0; adapters; adapters = adapters->Next, x++)
	{
		cout << "-- Adapter " << x << endl;
		cout << "Name: " << adapters->AdapterName << endl;
		cout << "Description: " << adapters->Description << endl;
		cout << "Adapter MAC:\t";
		for (UINT i = 0; i < adapters->AddressLength; i++)
			printf("%02X%c", adapters->Address[i], (i == adapters->AddressLength - 1 ? '\n' : '-'));
			//cout << setw(2) << setfill('0') << hex << (u_char)adapters->Address[i] << dec << (i == adapters->AddressLength - 1 ? '\n' : '-');

		for (n = 0, ipaddr_p = &adapters->IpAddressList; ipaddr_p; ipaddr_p = adapters->IpAddressList.Next, n++)
		{
			cout << "IP Address #" << n << ":\t" << ipaddr_p->IpAddress.String << " - ";
			cout << "Netmask:\t" << ipaddr_p->IpMask.String << endl;
		}
		for (n = 0, ipaddr_p = &adapters->GatewayList; ipaddr_p; ipaddr_p = adapters->GatewayList.Next, n++)
		{
			cout << "Gateway #" << n << ":\t" << ipaddr_p->IpAddress.String << " - ";
			cout << "Netmask:\t" << ipaddr_p->IpMask.String << endl;
		}
		cout << "Index:\t\t" << adapters->Index << endl;
		cout << "Type:\t\t";
		switch (adapters->Type)
		{
		case MIB_IF_TYPE_OTHER:
			cout << "Other (" << adapters->Type << ")" << endl;
			break;
		case MIB_IF_TYPE_ETHERNET:
			cout << "Ethernet (" << adapters->Type << ")" << endl;
			break;
		case MIB_IF_TYPE_TOKENRING:
			cout << "Token Ring (" << adapters->Type << ")" << endl;
			break;
		case MIB_IF_TYPE_FDDI:
			cout << "FDDI (" << adapters->Type << ")" << endl;
			break;
		case MIB_IF_TYPE_PPP:
			cout << "PPP (" << adapters->Type << ")" << endl;
			break;
		case MIB_IF_TYPE_LOOPBACK:
			cout << "Loopback (" << adapters->Type << ")" << endl;
			break;
		case MIB_IF_TYPE_SLIP:
			cout << "SLIP (" << adapters->Type << ")" << endl;
			break;
		default:
			cout << "Unknown (" << adapters->Type << ")" << endl;
			break;
		}

		cout << "DHCP Enabled:\t";
		if (adapters->DhcpEnabled)
		{
			cout << "Yes" << endl;
			for (n = 0, ipaddr_p = &adapters->DhcpServer; ipaddr_p; ipaddr_p = adapters->DhcpServer.Next, n++)
			{
				cout << "DHCP Server #" << n << ":\t" << ipaddr_p->IpAddress.String << " - ";
				cout << "Netmask:\t" << ipaddr_p->IpMask.String << endl;
			}
#if _MSC_VER != 1400		// 1400 = MSVC 2k5 Express (Beta?)
							// This part of the code crashes if compiled with MSVC 2k5 Express
			tm* LeaseTime;
			LeaseTime = localtime(&adapters->LeaseObtained);
			assert(LeaseTime);
			cout << "Lease obtained:\t" << LeaseTime->tm_mday << "/" << LeaseTime->tm_mon << "/" << LeaseTime->tm_year
				<< " at " << LeaseTime->tm_hour << ":" << LeaseTime->tm_min << ":" << LeaseTime->tm_sec << endl;
			LeaseTime = localtime(&adapters->LeaseExpires);
			assert(LeaseTime);
			cout << "Lease expires:\t" << LeaseTime->tm_mday << "/" << LeaseTime->tm_mon << "/" << LeaseTime->tm_year
				<< " at " << LeaseTime->tm_hour << ":" << LeaseTime->tm_min << ":" << LeaseTime->tm_sec << endl;
#endif
		}
		else
		{
			cout << "No" << endl;
		}
		cout << "Have Wins:\t";
		if (adapters->HaveWins)
		{
			cout << "Yes" << endl;
			cout << "Primary Wins Server: " << adapters->PrimaryWinsServer.IpAddress.String << " - ";
			cout << "Netmask:\t" << adapters->PrimaryWinsServer.IpMask.String << endl;
			cout << "Secondary Wins Server: " << adapters->SecondaryWinsServer.IpAddress.String << " - ";
			cout << "Netmask:\t" << adapters->PrimaryWinsServer.IpMask.String << endl;
		}
		else
		{
			cout << "No" << endl;
		}
	}
	delete adapts;
	adapts = 0;
	return true;
}


void CDEVICES::GetMACAddress()
{
// http://www.codeguru.com/Cpp/I-N/network/networkinformation/article.php/c5451
	/*IP_ADAPTER_INFO AdapterInfo[16];		// Allocate information
											// for up to 16 NICs
	DWORD dwBufLen = sizeof(AdapterInfo);	// Save memory size of buffer

	DWORD dwStatus = GetAdaptersInfo(		// Call GetAdapterInfo
	    AdapterInfo,						// [out] buffer to receive data
		&dwBufLen);							// [in] size of receive data buffer
	assert(dwStatus == ERROR_SUCCESS);		// Verify return value is
											// valid, no buffer overflow

	IP_ADAPTER_INFO* pAdapterInfo = AdapterInfo;	// Contains pointer to
													// current adapter info
	do
	{
		PrintMACaddress(pAdapterInfo->Address);	// Print MAC address
		pAdapterInfo->
		pAdapterInfo = pAdapterInfo->Next;		// Progress through
												// linked list
	} while(pAdapterInfo);						// Terminate if last adapter

	return macaddress*/
}

char* CDEVICES::GetDeviceName(char* rpcap_dev_name)
{
	assert(rpcap_dev_name);

	u_int length = strlen(pdevices->name) - 8;
	char* dev_name = new char[length + 1];
	assert(dev_name);
	memcpy(dev_name, rpcap_dev_name+8, length);
	dev_name[length] = '\0';
	return dev_name;
}