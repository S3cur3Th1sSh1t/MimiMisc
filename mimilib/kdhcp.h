/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "utils.h"
#include <dhcpssdk.h>

#define MAC_ADDRESS_SIZE			6
#define MAC_SOURCE_ADDRESS_OFFSET	28

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);
DWORD CALLBACK kdhcp_DhcpServerCalloutEntry(IN LPWSTR ChainDlls, IN DWORD CalloutVersion, IN OUT LPDHCP_CALLOUT_TABLE CalloutTbl);
DWORD CALLBACK kdhcp_DhcpNewPktHook(IN OUT LPBYTE *Packet, IN OUT DWORD *PacketSize, IN DWORD IpAddress, IN LPVOID Reserved, IN OUT LPVOID *PktContext, OUT LPBOOL ProcessIt);