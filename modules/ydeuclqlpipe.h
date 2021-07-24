/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"

BOOL ydeuclqlpipe_server(LPCWCHAR pipeName, HANDLE *phPipe);
BOOL ydeuclqlpipe_server_connect(HANDLE hPipe);
BOOL ydeuclqlpipe_client(LPCWCHAR pipeName, PHANDLE phPipe);
BOOL ydeuclqlpipe_read(HANDLE hPipe, LPBYTE *buffer, DWORD *size);
BOOL ydeuclqlpipe_write(HANDLE hPipe, LPCVOID buffer, DWORD size);
BOOL ydeuclqlpipe_close(PHANDLE phPipe);