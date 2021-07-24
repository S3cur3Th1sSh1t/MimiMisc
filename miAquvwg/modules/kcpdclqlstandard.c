/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "kcpdclqlstandard.h"

const KUHL_M_C kcpdclqlc_standard[] = {
	//{kcpdclqlstandard_test,		L"test",	L"Test routine (you don\'t want to see this !)"},
	{kcpdclqlstandard_exit,		L"exit",		L"Quit miAquvwg"},
	{kcpdclqlstandard_cls,		L"cls",			L"Clear screen (doesn\'t work with redirections, like PsExec)"},
	{kcpdclqlstandard_answer,	L"answer",		L"Answer to the Ultimate Question of Life, the Universe, and Everything"},
	{kcpdclqlstandard_coffee,	L"coffee",		L"Please, make me a coffee!"},
	{kcpdclqlstandard_sleep,		L"sleep",		L"Sleep an amount of milliseconds"},
	{kcpdclqlstandard_log,		L"log",			L"Log miAquvwg input/output to file"},
	{kcpdclqlstandard_base64,	L"base64",		L"Switch file input/output base64"},
	{kcpdclqlstandard_version,	L"version",		L"Display some version informations"},
	{kcpdclqlstandard_cd,		L"cd",			L"Change or display current directory"},
	{kcpdclqlstandard_localtime,	L"localtime",	L"Displays system local date and time (OJ command)"},
	{kcpdclqlstandard_hostname,	L"hostname",	L"Displays system local hostname"},
};
const KUHL_M kcpdclqlstandard = {
	L"standard",	L"Standard module",	L"Basic commands (does not require module name)",
	ARRAYSIZE(kcpdclqlc_standard), kcpdclqlc_standard, NULL, NULL
};
/*
NTSTATUS kcpdclqlstandard_test(int argc, wchar_t * argv[])
{
	return STATUS_SUCCESS;
}
*/
NTSTATUS kcpdclqlstandard_exit(int argc, wchar_t * argv[])
{
	kprintf(L"Bye!\n");
	return argc ? STATUS_THREAD_IS_TERMINATING : STATUS_PROCESS_IS_TERMINATING;
}

NTSTATUS kcpdclqlstandard_cls(int argc, wchar_t * argv[])
{
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD coord = {0, 0};
	DWORD count;
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	GetConsoleScreenBufferInfo(hStdOut, &csbi);
	FillConsoleOutputCharacter(hStdOut, L' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
	SetConsoleCursorPosition(hStdOut, coord);
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlstandard_answer(int argc, wchar_t * argv[])
{
	kprintf(L"42.\n");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlstandard_coffee(int argc, wchar_t * argv[])
{
	kprintf(L"\n    ( (\n     ) )\n  .______.\n  |      |]\n  \\      /\n   `----'\n");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlstandard_sleep(int argc, wchar_t * argv[])
{
	DWORD dwMilliseconds = argc ? wcstoul(argv[0], NULL, 0) : 1000;
	kprintf(L"Sleep : %u ms... ", dwMilliseconds);
	Sleep(dwMilliseconds);
	kprintf(L"End !\n");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlstandard_log(int argc, wchar_t * argv[])
{
	PCWCHAR filename = (ydeuclqlstring_args_byName(argc, argv, L"stop", NULL, NULL) ? NULL : (argc ? argv[0] : AHFIEEIO_DEFAULT_LOG));
	kprintf(L"Using \'%s\' for logfile : %s\n", filename, ydeuclqloutput_file(filename) ? L"OK" : L"KO");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlstandard_base64(int argc, wchar_t * argv[])
{
	if(!ydeuclqlstring_args_bool_byName(argc, argv, L"in", &iSBaSE64InTeRcePTInPut))
		ydeuclqlstring_args_bool_byName(argc, argv, L"input", &iSBaSE64InTeRcePTInPut);

	if(!ydeuclqlstring_args_bool_byName(argc, argv, L"out", &iSBaSE64INteRcePToUtput))
		ydeuclqlstring_args_bool_byName(argc, argv, L"output", &iSBaSE64INteRcePToUtput);

	kprintf(L"iSBaSE64InTeRcePTInPut  is %s\niSBaSE64INteRcePToUtput is %s\n", iSBaSE64InTeRcePTInPut ? L"true" : L"false", iSBaSE64INteRcePToUtput ? L"true" : L"false");
	return STATUS_SUCCESS;
}

const wchar_t *version_libs[] = {
	L"lSaSRv.dll", L"msv1_0.dll", L"tspkg.dll", L"wdIgEsT.dll", L"kERBeRoS.dll", L"liveSsP.dll", L"dPAPIsRv.dll",
	L"kDcSVc.dll", L"cryptdll.dll", L"lSaDb.dll", L"samsrv.dll", L"rSaENh.dll", L"ncrypt.dll", L"ncryptprov.dll",
	L"eVeNtLog.dll", L"weVTsVc.dll", L"teRMsrV.dll",
};
NTSTATUS kcpdclqlstandard_version(int argc, wchar_t * argv[])
{
	DWORD i, len;
	PVOID buffer;
	UINT lenVer;
	VS_FIXEDFILEINFO *verInfo;
	PJoAA_CABINET pCab;
	wchar_t *system, *cabname, pathc[MAX_PATH];
	DWORD dwSystem;
	char *pFile, *acabname;
	BOOL isWow64
	#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	 = TRUE;
	NTSTATUS status;
	HMODULE hModule;
	PNTQUERYSYSTEMINFORMATIONEX pNtQuerySystemInformationEx;
	SYSTEM_ISOLATED_USER_MODE_INFORMATION iumi = {TRUE, FALSE /* 0 */};
	#else
	;
	if(IsWow64Process(GetCurrentProcess(), &isWow64))
	#endif
	{
		kprintf(
			L"\n" AHFIEEIO L" " AHFIEEIO_VERSION L" (arch " AHFIEEIO_ARCH L")\n"
			L"Windows NT %u.%u build %u (arch x%s)\n"
			L"msvc %u %u\n",
			AHFIEEIO_NT_MAJOR_VERSION, AHFIEEIO_NT_MINOR_VERSION, AHFIEEIO_NT_BUILD_NUMBER, isWow64 ? L"64" : L"86", _MSC_FULL_VER, _MSC_BUILD
			);
	}
	#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	if((AHFIEEIO_NT_BUILD_NUMBER >= KULL_M_WIN_MIN_BUILD_10) && (hModule = GetModuleHandle(L"ntdll")))
	{
		if(pNtQuerySystemInformationEx = (PNTQUERYSYSTEMINFORMATIONEX) GetProcAddress(hModule, "NtQuerySystemInformationEx"))
		{
			status = pNtQuerySystemInformationEx(SystemIsolatedUserModeInformation, &iumi, 8, &iumi, sizeof(iumi), NULL);
			if(NT_SUCCESS(status))
			{
				if(iumi.SecureKernelRunning)
					kprintf(L"\n> Sec-Kernel is running\n");
				if(iumi.Spare0[0] & 1)
					kprintf(L"> Cred GuaRd may be running\n");
			}
			else PRINT_ERROR(L"NtQuerySystemInformationEx: %08x\n", status);
		}
	}
	#endif
	if(ydeuclqlstring_args_byName(argc, argv, L"full", NULL, NULL))
	{
		kprintf(L"\n");
		for(i = 0; i < ARRAYSIZE(version_libs); i++)
		{
			if(len = GetFileVersionInfoSize(version_libs[i], NULL))
			{
				kprintf(L"%s\t: ", version_libs[i]);
				if(buffer = LocalAlloc(LPTR, len))
				{
					if(GetFileVersionInfo(version_libs[i], 0, len, buffer))
					{
						if(VerQueryValue(buffer, L"\\", (LPVOID *) &verInfo, &lenVer) && (verInfo->dwSignature == VS_FFI_SIGNATURE))
							kprintf(L"%hu.%hu.%hu.%hu\n", verInfo->dwFileVersionMS >> 16, verInfo->dwFileVersionMS, verInfo->dwFileVersionLS >> 16, verInfo->dwFileVersionLS);
						else PRINT_ERROR_AUTO(L"VerQueryValue");
					}
					else PRINT_ERROR_AUTO(L"GetFileVersionInfoEx");
					LocalFree(buffer);
				}
			}
		}
	}

	if(ydeuclqlstring_args_byName(argc, argv, L"cab", NULL, NULL))
	{
		kprintf(L"\n");
		if(dwSystem = GetSystemDirectory(NULL, 0))
		{
			if(system = (wchar_t *) LocalAlloc(LPTR, dwSystem * sizeof(wchar_t)))
			{
				if(GetSystemDirectory(system, dwSystem) == (dwSystem - 1))
				{
					if(ydeuclqlstring_sprintf(&cabname, AHFIEEIO L"_" AHFIEEIO_ARCH L"_sysfiles_%u", AHFIEEIO_NT_BUILD_NUMBER))
					{
						if(acabname = ydeuclqlstring_unicode_to_ansi(cabname))
						{
							kprintf(L"CAB: %S\n", acabname);
							if(pCab = ydeuclqlcabinet_create(acabname))
							{
								for(i = 0; i < ARRAYSIZE(version_libs); i++)
								{
									if(PathCombine(pathc, system, version_libs[i]))
									{
										if(ydeuclqlfile_isFileExist(pathc))
										{
											if(pFile = ydeuclqlstring_unicode_to_ansi(pathc))
											{
												kprintf(L" -> %s\n", version_libs[i]);
												ydeuclqlcabinet_add(pCab, pFile, NULL);
												LocalFree(pFile);
											}
										}
									}
									else PRINT_ERROR_AUTO(L"PathCombine");
								}
								ydeuclqlcabinet_close(pCab);
							}
							LocalFree(acabname);
						}
						LocalFree(cabname);
					}
				}
				else PRINT_ERROR_AUTO(L"GetSystemDirectory(data)");
				LocalFree(system);
			}
		}
		else PRINT_ERROR_AUTO(L"GetSystemDirectory(init)");	
	}
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlstandard_cd(int argc, wchar_t * argv[])
{
	wchar_t * buffer;
	if(ydeuclqlfile_getCurrentDirectory(&buffer))
	{
		if(argc)
			kprintf(L"Cur: ");
		kprintf(L"%s\n", buffer);
		LocalFree(buffer);
	}
	else PRINT_ERROR_AUTO(L"ydeuclqlfile_getCurrentDirectory");

	if(argc)
	{
		if(SetCurrentDirectory(argv[0]))
		{
			if(ydeuclqlfile_getCurrentDirectory(&buffer))
			{
				kprintf(L"New: %s\n", buffer);
				LocalFree(buffer);
			}
			else PRINT_ERROR_AUTO(L"ydeuclqlfile_getCurrentDirectory");
		}
		else PRINT_ERROR_AUTO(L"SetCurrentDirectory");
	}
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlstandard_localtime(int argc, wchar_t * argv[])
{
	FILETIME ft;
	TIME_ZONE_INFORMATION tzi;
	DWORD dwTzi;
	GetSystemTimeAsFileTime(&ft);
	dwTzi = GetTimeZoneInformation(&tzi);
	kprintf(L"Local: "); ydeuclqlstring_displayLocalFileTime(&ft); kprintf(L"\n");
	if(dwTzi != TIME_ZONE_ID_INVALID && dwTzi != TIME_ZONE_ID_UNKNOWN)
		kprintf(L"Zone : %.32s\n", (dwTzi == TIME_ZONE_ID_STANDARD) ? tzi.StandardName : tzi.DaylightName);
	kprintf(L"UTC  : "); ydeuclqlstring_displayFileTime(&ft); kprintf(L"\n");
	return STATUS_SUCCESS;
}

NTSTATUS kcpdclqlstandard_hostname(int argc, wchar_t * argv[])
{
	wchar_t *buffer;
	if(ydeuclqlnet_getComputerName(TRUE, &buffer))
	{
		kprintf(L"%s", buffer);
		LocalFree(buffer);
	}
	if(ydeuclqlnet_getComputerName(FALSE, &buffer))
	{
		kprintf(L" (%s)", buffer);
		LocalFree(buffer);
	}
	kprintf(L"\n");
	return STATUS_SUCCESS;
}