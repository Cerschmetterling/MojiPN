typedef __int16 uint16_t;
typedef __int32 uint32_t;
typedef __int8  uint8_t;

#include <iostream>
#include "windivert.h"
#include "mynetworking.h"
#include <string>


using namespace std;

bool processPackage(char* package);
int main()
{
	HANDLE handle;          // WinDivert handle
	WINDIVERT_ADDRESS addr; // Packet address
	char packet[MAXBUF];    // Packet buffer
	UINT packetLen;
	bool further = true;
	handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);   // Open some filter
	if (handle == INVALID_HANDLE_VALUE)
	{
		// Handle error
		cout << handle;
		exit(1);
	}

	// Main capture-modify-inject loop:
	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen))
		{
			// Handle recv error
			continue;
		}
		further = processPackage(packet);
		if (further){
			if (!WinDivertSend(handle, packet, packetLen, &addr, NULL))
			{
				// Handle send error
				continue;
			}
		}
	}
	WinDivertClose(handle);
	return 0;
}


bool processPackage(char* package){
	return true;
}
