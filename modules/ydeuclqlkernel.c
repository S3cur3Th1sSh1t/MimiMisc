/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#include "ydeuclqlkernel.h"

BOOL ydeuclqlkernel_ioctl_handle(HANDLE hDriver, DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer)
{
	BOOL status = FALSE;
	DWORD lStatus = ERROR_MORE_DATA, returned;

	if(!autobuffer)
	{
		status = DeviceIoControl(hDriver, ioctlCode, bufferIn, szBufferIn, pBufferOut ? *pBufferOut : NULL, pSzBufferOut ? *pSzBufferOut : 0, &returned, NULL);
	}
	else
	{
		for(*pSzBufferOut = 0x10000; (lStatus == ERROR_MORE_DATA) && (*pBufferOut = LocalAlloc(LPTR, *pSzBufferOut)) ; *pSzBufferOut <<= 1)
		{
			if(status = DeviceIoControl(hDriver, ioctlCode, bufferIn, szBufferIn, *pBufferOut, *pSzBufferOut, &returned, NULL))
			{
				lStatus = ERROR_SUCCESS;
			}
			else
			{
				lStatus = GetLastError();
				if(lStatus == ERROR_MORE_DATA)
					LocalFree(*pBufferOut);
			}
		}
	}
	if(!status)
	{
		PRINT_ERROR(L"DeviceIoControl (0x%08x) : 0x%08x\n", ioctlCode, GetLastError());
		if(autobuffer)
			LocalFree(*pBufferOut);
	}
	else if(pSzBufferOut)
		*pSzBufferOut = returned;
	return status;
}

BOOL ydeuclqlkernel_ioctl(PCWSTR driver, DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer)
{
	BOOL status = FALSE;
	HANDLE hDriver;
	hDriver = CreateFile(driver, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hDriver && hDriver != INVALID_HANDLE_VALUE)
	{
		status = ydeuclqlkernel_ioctl_handle(hDriver, ioctlCode, bufferIn, szBufferIn, pBufferOut, pSzBufferOut, autobuffer);
		CloseHandle(hDriver);
	}
	else
		PRINT_ERROR_AUTO(L"CreateFile");
	return status;
}

BOOL ydeuclqlkernel_mimidrv_ioctl(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn, PVOID * pBufferOut, PDWORD pSzBufferOut, BOOL autobuffer)
{
	return ydeuclqlkernel_ioctl(L"\\\\.\\" AHFIEEIO_DRIVER, ioctlCode, bufferIn, szBufferIn, pBufferOut, pSzBufferOut, autobuffer);
}

BOOL ydeuclqlkernel_mimidrv_simple_output(DWORD ioctlCode, PVOID bufferIn, DWORD szBufferIn)
{
	BOOL status = FALSE;
	PVOID buffer = NULL;
	DWORD i, szBuffer;

	if(status = ydeuclqlkernel_ioctl(L"\\\\.\\" AHFIEEIO_DRIVER, ioctlCode, bufferIn, szBufferIn, &buffer, &szBuffer, TRUE))
	{
		for(i = 0; i < szBuffer / sizeof(wchar_t); i++)
			kprintf(L"%c", ((wchar_t *) buffer)[i]);
		LocalFree(buffer);
	}
	return status;
}