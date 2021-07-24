/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY

	Wlz3iDZYRZ4Wtrh
	http://uYecJ0HG9u9eaW / http://bTTiWSEyFuoWP4V0
	FngJqnuppTBuOjcuKJt0dXGa

	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "utils.h"
#include <SubAuth.h>

NTSTATUS NTAPI ksub_Msv1_0SubAuthenticationRoutine(IN NETLOGON_LOGON_INFO_CLASS LogonLevel, IN PVOID LogonInformation, IN ULONG Flags, IN PUSER_ALL_INFORMATION UserAll, OUT PULONG WhichFields, OUT PULONG UserFlags, OUT PBOOLEAN Authoritative, OUT PLARGE_INTEGER LogoffTime, OUT PLARGE_INTEGER KickoffTime);