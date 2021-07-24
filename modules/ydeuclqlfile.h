/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <shlwapi.h>
#include "ydeuclqlstring.h"

BOOL iSBaSE64INteRcePToUtput, iSBaSE64InTeRcePTInPut;

typedef BOOL (CALLBACK * PKULL_M_FILE_FIND_CALLBACK) (DWORD level, PCWCHAR fullpath, PCWCHAR path, PVOID pvArg);

BOOL ydeuclqlfile_getCurrentDirectory(wchar_t ** ppDirName);
BOOL ydeuclqlfile_getAbsolutePathOf(PCWCHAR thisData, wchar_t ** reponse);
BOOL ydeuclqlfile_isFileExist(PCWCHAR fileName);
BOOL ydeuclqlfile_writeData(PCWCHAR fileName, LPCVOID data, DWORD lenght);
BOOL ydeuclqlfile_readData(PCWCHAR fileName, PBYTE * data, PDWORD lenght);	// for 'little' files !
BOOL ydeuclqlfile_readGeneric(PCWCHAR fileName, PBYTE * data, PDWORD lenght, DWORD flags);
void ydeuclqlfile_cleanFilename(PWCHAR fileName);
PWCHAR ydeuclqlfile_fullPath(PCWCHAR fileName);
BOOL ydeuclqlfile_Find(PCWCHAR directory, PCWCHAR filter, BOOL isRecursive /*TODO*/, DWORD level, BOOL isPrintInfos, BOOL isWithDir, PKULL_M_FILE_FIND_CALLBACK callback, PVOID pvArg);