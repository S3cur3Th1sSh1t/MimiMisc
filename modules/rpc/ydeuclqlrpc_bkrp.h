/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "ydeuclqlrpc_ms-bkrp.h"
#include "../ydeuclqlnet.h"

BOOL ydeuclqlrpc_bkrp_createBinding(LPCWSTR NetworkAddr, RPC_BINDING_HANDLE *hBinding);

BOOL ydeuclqlrpc_bkrp_generic(LPCWSTR NetworkAddr, const GUID * pGuid, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut);

BOOL ydeuclqlrpc_bkrp_Restore(LPCWSTR NetworkAddr, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut);
BOOL ydeuclqlrpc_bkrp_Backup(LPCWSTR NetworkAddr, PVOID DataIn, DWORD dwDataIn, PVOID *pDataOut, DWORD *pdwDataOut);
BOOL ydeuclqlrpc_bkrp_BackupKey(LPCWSTR NetworkAddr, PVOID *pDataOut, DWORD *pdwDataOut);