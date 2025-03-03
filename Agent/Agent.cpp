// Agent.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "Fwpuclnt")

std::wstring GuidToString(GUID const& guid)
{
	WCHAR sGuid[64];
	return ::StringFromGUID2(guid, sGuid, _countof(sGuid)) ? sGuid : L"";
}

const char* ActionToString(FWPM_ACTION const& action)
{
	switch (action.type)
	{
		case FWP_ACTION_BLOCK:					return "Block";
		case FWP_ACTION_PERMIT:					return "Permit";
		case FWP_ACTION_CALLOUT_TERMINATING:	return "Callout Terminating";
		case FWP_ACTION_CALLOUT_INSPECTION:		return "Callout Inspection";
		case FWP_ACTION_CALLOUT_UNKNOWN:		return "Callout Unknown";
		case FWP_ACTION_CONTINUE:				return "Continue";
		case FWP_ACTION_NONE:					return "None";
		case FWP_ACTION_NONE_NO_MATCH:			return "None (No Match)";
	}
	return "";
}

void EnumFilters(PHANDLE hpEngine)
{
	HANDLE hEnum;
	HANDLE hEngine = *hpEngine;
	FwpmFilterCreateEnumHandle(hEngine, NULL, &hEnum);

	UINT32 count;
	FWPM_FILTER** filters;
	FwpmFilterEnum(hEngine, hEnum, 8192 /*Max entries*/, &filters/*Returned results*/, &count /*How many we got*/);

	for (UINT32 i = 0; i < count; i++)
	{
		auto f = filters[i];
		printf("[-%d-]| %ws Name: %-40ws Id: 0x%08X Conditions: %2u Action: %s\n",
			i,
			GuidToString(f->filterKey).c_str(),
			f->displayData.name,
			f->filterId,
			f->numFilterConditions,
			ActionToString(f->action));
	}

	FwpmFreeMemory((void**)&filters);
	FwpmFilterDestroyEnumHandle(hEngine, hEnum);

}

int main()
{
	printf("WFP enumeration\n");
	
	HANDLE hEngine;
	FWPM_FILTER filter{};
	WCHAR filterName[] = L"Prevent Calculator from accessing the web";
	filter.displayData.name = filterName;

	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	filter.action.type = FWP_ACTION_BLOCK;
	
	WCHAR filename[] = LR"(C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2411.1.0_x64__8wekyb3d8bbwe\CalculatorApp.exe)";
	FWP_BYTE_BLOB* appId;
	FwpmGetAppIdFromFileName(filename, &appId);

	FWPM_FILTER_CONDITION cond;
	cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
	cond.matchType = FWP_MATCH_EQUAL;
	cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
	cond.conditionValue.byteBlob = appId;

	filter.filterCondition = &cond;
	filter.numFilterConditions = 1;

	FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
	//EnumFilters(&hEngine);

	FwpmFilterAdd(hEngine, &filter, NULL, NULL);

	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	FwpmFilterAdd(hEngine, &filter, NULL, NULL);

	FwpmFreeMemory((void**)&appId);
	FwpmEngineClose(hEngine);

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
