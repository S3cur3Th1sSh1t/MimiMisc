/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <io.h>
#include <fcntl.h>

FILE * logfile;
#if !defined(AHFIEEIO_W2000_SUPPORT)
wchar_t * outputBuffer;
size_t outputBufferElements, outputBufferElementsPosition;
#endif

void kprintf(PCWCHAR format, ...);
void kprintf_inputline(PCWCHAR format, ...);

BOOL ydeuclqloutput_file(PCWCHAR file);

void ydeuclqloutput_init();
void ydeuclqloutput_clean();