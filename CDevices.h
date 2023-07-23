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
#ifndef _CDevices_H_
#define _CDevices_H_
#include "StdAfx.h"
#include "CLog.h"
#include <Iphlpapi.h>
#include <time.h>

class CDEVICES {
protected:
	// variables
	pcap_if_t * devices;				// holds all devices
	pcap_if_t * pdevices;				// pointer to devices
	pcap_addr_t * device_addr;			// pointer to device address info
	int n_devices;						// number of devices found
	char errorbuf[PCAP_ERRBUF_SIZE+1];	// buffer holding last error string

	// functions
	bool InitializeDevices();			// gets called by CDEVICES::CDEVICES();
	char* GetDeviceName(char* rpcap_dev_name);
	void GetMACAddress();

private:
	// variables
	socklen_t sockaddrlen;				// sizeof ipv6 struct, differs from OS

public:
	CDEVICES();
	virtual ~CDEVICES();

	// variables
	CLog log;							// log class

	// functions
	bool ShowAllDevices();
	bool ShowAllDevicesInfo();
	bool ShowDeviceInformation(int device);
	void ShowLastError();
	virtual bool SnifPacketsOnDevice(int device);
	virtual bool SendPacketsToDevice(int device);

};

#endif