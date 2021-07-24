/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpdclqlservice.h"
#if defined(SERVICE_INCONTROL)
#include "../modules/ydeuclqlremotelib.h"
#include "../modules/ydeuclqlpatch.h"

typedef DWORD ( __stdcall * PSCSENDCONTROL_STD)	(LPCWSTR lpServiceName, PVOID arg1, PVOID arg2, int arg3, DWORD dwControl, DWORD arg4, PVOID arg5, DWORD arg6, PVOID arg7, DWORD arg8, DWORD arg9, PVOID arg10, PVOID arg11, PVOID arg12);
typedef DWORD (__fastcall * PSCSENDCONTROL_FAST)(LPCWSTR lpServiceName, PVOID arg1, PVOID arg2, int arg3, DWORD dwControl, DWORD arg4, PVOID arg5, DWORD arg6, PVOID arg7, DWORD arg8, DWORD arg9, PVOID arg10, PVOID arg11, PVOID arg12);

DWORD WINAPI kcpd_service_sendcontrol_std_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kcpd_service_sendcontrol_std_thread_end();
DWORD WINAPI kcpd_service_sendcontrol_fast_thread(PREMOTE_LIB_DATA lpParameter);
DWORD kcpd_service_sendcontrol_fast_thread_end();

BOOL kcpd_service_sendcontrol_inprocess(PWSTR ServiceName, DWORD dwControl);
#endif