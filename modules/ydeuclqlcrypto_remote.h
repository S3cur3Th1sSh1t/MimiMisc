/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "ydeuclqlremotelib.h"

//typedef BOOL (WINAPI * PCRYPTPROTECTMEMORY) (__inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);
typedef BOOL (WINAPI * PCRYPTUNPROTECTMEMORY) (__inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);

BOOL WINAPI ydeuclqlcrypto_remote_CryptProtectMemory_Generic(__in PKULL_M_MEMORY_HANDLE hProcess, __in BOOL bIsProtect, __inout LPVOID pDataIn, __in DWORD cbDataIn, __in DWORD dwFlags);

#define ydeuclqlcrypto_remote_CryptProtectMemory(hProcess, pDataIn, cbDataIn, dwFlags)	ydeuclqlcrypto_remote_CryptProtectMemory_Generic(hProcess, TRUE, pDataIn, cbDataIn, dwFlags)
#define ydeuclqlcrypto_remote_CryptUnprotectMemory(hProcess, pDataIn, cbDataIn, dwFlags)	ydeuclqlcrypto_remote_CryptProtectMemory_Generic(hProcess, FALSE, pDataIn, cbDataIn, dwFlags)