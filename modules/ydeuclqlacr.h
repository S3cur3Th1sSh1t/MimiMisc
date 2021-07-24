/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include "ydeuclqlstring.h"

#define IOCTL_CCID_ESCAPE SCARD_CTL_CODE(3500)

#define ACR_MAX_LEN					255

typedef struct _KULL_M_ACR_COMM {
	//SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	BOOL withoutCard;
	LPVOID suppdata;
	BOOL descr;
} KULL_M_ACR_COMM, *PKULL_M_ACR_COMM;

BOOL ydeuclqlacr_init(SCARDCONTEXT hContext, LPCWSTR szReaderName, BOOL withoutCard, LPVOID suppdata, BOOL descr, PKULL_M_ACR_COMM comm);
void ydeuclqlacr_finish(PKULL_M_ACR_COMM comm);
BOOL ydeuclqlarc_sendrecv(PKULL_M_ACR_COMM comm, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult);
BOOL ydeuclqlacr_sendrecv_ins(PKULL_M_ACR_COMM comm, BYTE cla, BYTE ins, BYTE p1, BYTE p2, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, BOOL noLe);
BOOL CALLBACK ydeuclqlarcr_SendRecvDirect(const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult, LPVOID suppdata);