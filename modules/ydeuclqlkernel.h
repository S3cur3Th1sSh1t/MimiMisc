/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <winioctl.h>
#include "../mimidrv/ioctl.h"

BOOL ydeuclqlkernel_ioctl_handle(HANDLE hDriver, DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer);
BOOL ydeuclqlkernel_ioctl(PCWSTR driver, DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer);
BOOL ydeuclqlkernel_mimidrv_ioctl(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer);
BOOL ydeuclqlkernel_mimidrv_simple_output(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn);