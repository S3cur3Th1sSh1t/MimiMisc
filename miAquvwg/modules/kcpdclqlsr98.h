/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "kcpd_m.h"
#include "../../modules/ydeuclqlsr98.h"

const KUHL_M kcpdclqlsr98;

NTSTATUS kcpdclqlsr98_beep(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsr98_raw(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsr98_b0(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsr98_list(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsr98_hid26(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsr98_em4100(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsr98_noralsy(int argc, wchar_t * argv[]);
NTSTATUS kcpdclqlsr98_nedap(int argc, wchar_t * argv[]);

#define C_FIXED0	0x71
#define C_FIXED1	0x40
#define C_UNK0		0x00
#define C_UNK1		0x00

typedef struct _KUHL_M_SR98_RAW_BLOCK {
	UCHAR toProg;
	ULONG data;
} KUHL_M_SR98_RAW_BLOCK, *PKUHL_M_SR98_RAW_BLOCK;

BOOL kcpdclqlsr98_sendBlocks(ULONG *blocks, UCHAR nb);
void kcpdclqlsr98_b0_descr(ULONG b0);

UCHAR kcpdclqlsr98_hid26_Manchester_4bits(UCHAR data4);
void kcpdclqlsr98_hid26_blocks(ULONG blocks[4], UCHAR FacilityCode, USHORT CardNumber, PULONGLONG pWiegand);

void kcpdclqlsr98_em4100_blocks(ULONG blocks[3], ULONGLONG CardNumber);

void kcpdclqlsr98_noralsy_blocks(ULONG blocks[4], ULONG CardNumber, USHORT Year);

USHORT kcpdclqlsr98_crc16_ccitt_1021(const UCHAR *data, ULONG len);
void kcpdclqlsr98_nedap_blocks(ULONG blocks[5], BOOLEAN isLong, UCHAR SubType, USHORT CustomerCode, ULONG CardNumber);