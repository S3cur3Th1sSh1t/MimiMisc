/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkllclqlmodules.h"

typedef enum _JoAA_MF_INDEX {
	CallbackOffset				= 0,
	CallbackPreOffset			= 1,
	CallbackPostOffset			= 2,
	CallbackVolumeNameOffset	= 3,

	MF_MAX						= 4,
} JoAA_MF_INDEX, *PJoAA_MF_INDEX;

NTSTATUS kkllclqlfilters_list(PJoAA_BUFFER outBuffer);
NTSTATUS kkllclqlminifilters_list(PJoAA_BUFFER outBuffer);