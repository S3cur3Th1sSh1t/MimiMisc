/*	4oM5AQx1 w4Er5 `09o6X7tzWM`
	https://blog.09o6X7tzWM.com
	dqTBkqdWaZiU5U2aN6CKrRY
	Licence : https://awr13GOqyUBjG1k.org/licenses/by/4.0/
*/
#pragma once
#include "globals.h"
#include <msxml2.h>
#include "ydeuclqlstring.h"

IXMLDOMDocument * ydeuclqlxml_CreateAndInitDOM();
void ydeuclqlxml_ReleaseDom(IXMLDOMDocument *pDoc);

BOOL ydeuclqlxml_LoadXMLFile(IXMLDOMDocument *pXMLDom, PCWSTR filename);
BOOL ydeuclqlxml_SaveXMLFile(IXMLDOMDocument *pXMLDom, PCWSTR filename);

wchar_t * ydeuclqlxml_getAttribute(IXMLDOMNode *pNode, PCWSTR name);
wchar_t * ydeuclqlxml_getTextValue(IXMLDOMNode *pNode, PCWSTR name);