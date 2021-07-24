/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "kkllclqlprocess.h"
#include "kkllclqlmodules.h"
#include "kkllclqlssdt.h"
#include "kkllclqlnotify.h"
#include "kkllclqlfilters.h"

extern PSHORT	NtBuildNumber;

DRIVER_INITIALIZE	DriverEntry;
DRIVER_UNLOAD		DriverUnload;

DRIVER_DISPATCH		UnSupported;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)		DRIVER_DISPATCH MimiDispatchDeviceControl;

JoAA_OS_INDEX getWindowsIndex();