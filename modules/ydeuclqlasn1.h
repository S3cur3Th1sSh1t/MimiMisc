/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <Winldap.h>
#include <Winber.h>
#include <msasn1.h>
#include "ydeuclqlstring.h"

#define DIRTY_ASN1_ID_BOOLEAN			0x01
#define DIRTY_ASN1_ID_INTEGER			0x02
#define DIRTY_ASN1_ID_BIT_STRING		0x03
#define DIRTY_ASN1_ID_OCTET_STRING		0x04
#define DIRTY_ASN1_ID_NULL				0x05
#define DIRTY_ASN1_ID_OBJECT_IDENTIFIER	0x06
#define DIRTY_ASN1_ID_GENERAL_STRING	0x1b
#define DIRTY_ASN1_ID_GENERALIZED_TIME	0x18
#define DIRTY_ASN1_ID_SEQUENCE			0x30

#define DIRTY_ASN1_MASK_APPLICATION		0x60
#define DIRTY_ASN1_MASK_CONTEXT			0xa0

#define MAKE_APP_TAG(AppId)		((ber_tag_t) (DIRTY_ASN1_MASK_APPLICATION | AppId))
#define MAKE_CTX_TAG(CtxId)		((ber_tag_t) (DIRTY_ASN1_MASK_CONTEXT | CtxId))

void ydeuclqlasn1_BitStringFromULONG(BerElement * pBer, ULONG data);
void ydeuclqlasn1_GenTime(BerElement * pBer, PFILETIME localtime);
void ydeuclqlasn1_GenString(BerElement * pBer, PCUNICODE_STRING String);

typedef struct {
    unsigned short length;
    unsigned char *value;
} OssEncodedOID;

extern ASN1_PUBLIC BOOL ASN1API ASN1BERDotVal2Eoid(__in ASN1encoding_t pEncoderInfo, __in const ASN1char_t *dotOID, __out OssEncodedOID *encodedOID);
extern ASN1_PUBLIC BOOL ASN1API ASN1BEREoid2DotVal(__in ASN1decoding_t pDecoderInfo, __in const OssEncodedOID *encodedOID, __out ASN1char_t **dotOID);

BOOL ydeuclqlasn1_init();
void ydeuclqlasn1_term();
BOOL ydeuclqlasn1_DotVal2Eoid(__in const ASN1char_t *dotOID, __out OssEncodedOID *encodedOID);
void ydeuclqlasn1_freeEnc(void *pBuf);
BOOL ydeuclqlasn1_Eoid2DotVal(__in const OssEncodedOID *encodedOID, __out ASN1char_t **dotOID);
void ydeuclqlasn1_freeDec(void *pBuf);