/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <dbghelp.h>

typedef struct _KULL_M_MINIDUMP_HANDLE {
	HANDLE hFileMapping;
	LPVOID pMapViewOfFile;
} KULL_M_MINIDUMP_HANDLE, *PKULL_M_MINIDUMP_HANDLE;

BOOL ydeuclqlminidump_open(IN HANDLE hFile, OUT PKULL_M_MINIDUMP_HANDLE *hMinidump);
BOOL ydeuclqlminidump_close(IN PKULL_M_MINIDUMP_HANDLE hMinidump);
BOOL ydeuclqlminidump_copy(IN PKULL_M_MINIDUMP_HANDLE hMinidump, OUT VOID *Destination, IN VOID *Source, IN SIZE_T Length);

LPVOID ydeuclqlminidump_RVAtoPTR(IN PKULL_M_MINIDUMP_HANDLE hMinidump, RVA64 rva);
LPVOID ydeuclqlminidump_stream(IN PKULL_M_MINIDUMP_HANDLE hMinidump, MINIDUMP_STREAM_TYPE type, OUT OPTIONAL DWORD *pSize);
LPVOID ydeuclqlminidump_remapVirtualMemory64(IN PKULL_M_MINIDUMP_HANDLE hMinidump, IN VOID *Source, IN SIZE_T Length);