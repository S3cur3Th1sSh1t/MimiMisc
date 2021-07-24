/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "utils.h"

#define PLUGIN_ALLOCATOR_FUNCTION PVOID
#define PLUGIN_FREE_FUNCTION PVOID
#define PDB_RECORD PVOID

DWORD WINAPI kdns_DnsPluginInitialize(PLUGIN_ALLOCATOR_FUNCTION pDnsAllocateFunction, PLUGIN_FREE_FUNCTION pDnsFreeFunction);
DWORD WINAPI kdns_DnsPluginCleanup();
DWORD WINAPI kdns_DnsPluginQuery(PSTR pszQueryName, WORD wQueryType, PSTR pszRecordOwnerName, PDB_RECORD *ppDnsRecordListHead);
// DnsPluginQuery2
// DnsPluginQueryZoneScope
// DnsPluginQueryServerScope
// DnsPluginQueryCacheScope