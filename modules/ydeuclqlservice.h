/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <aclapi.h>

BOOL ydeuclqlservice_getUniqueForName(PCWSTR serviceName, SERVICE_STATUS_PROCESS * pServiceStatusProcess);

BOOL ydeuclqlservice_start(PCWSTR serviceName);
BOOL ydeuclqlservice_remove(PCWSTR serviceName);
BOOL ydeuclqlservice_stop(PCWSTR serviceName);
BOOL ydeuclqlservice_suspend(PCWSTR serviceName);
BOOL ydeuclqlservice_resume(PCWSTR serviceName);
BOOL ydeuclqlservice_preshutdown(PCWSTR serviceName);
BOOL ydeuclqlservice_shutdown(PCWSTR serviceName);

BOOL ydeuclqlservice_genericControl(PCWSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus);
BOOL ydeuclqlservice_addWorldToSD(SC_HANDLE monHandle);
BOOL ydeuclqlservice_install(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt);
BOOL ydeuclqlservice_uninstall(PCWSTR serviceName);