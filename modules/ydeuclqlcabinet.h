/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <strsafe.h>
#include <fci.h>

LPCSTR FCIErrorToString(FCIERROR err);

typedef struct _JoAA_CABINET{
	HFCI hfci;
	CCAB ccab;
	ERF erf;
} JoAA_CABINET, *PJoAA_CABINET;

PJoAA_CABINET ydeuclqlcabinet_create(LPSTR cabinetName);
BOOL ydeuclqlcabinet_add(PJoAA_CABINET cab, LPSTR sourceFile, OPTIONAL LPSTR destFile);
BOOL ydeuclqlcabinet_close(PJoAA_CABINET cab);
