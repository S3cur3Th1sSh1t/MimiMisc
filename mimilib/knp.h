/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "utils.h"
#include <npapi.h>

DWORD WINAPI knp_NPLogonNotify(PLUID lpLogonId, LPCWSTR lpAuthentInfoType, LPVOID lpAuthentInfo, LPCWSTR lpPreviousAuthentInfoType, LPVOID lpPreviousAuthentInfo, LPWSTR lpStationName, LPVOID StationHandle, LPWSTR *lpLogonScript);
DWORD WINAPI knp_NPGetCaps(DWORD nIndex);