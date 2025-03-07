// Agent.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <string>
#include "..\FirewallDrv\common.h"

#pragma comment(lib, "Fwpuclnt")

DWORD RegisterProviders()
{
	HANDLE hEngine;
	DWORD error = FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
	if (error)
	{
		return error;
	}

	FWPM_PROVIDER* provider;
	error = FwpmProviderGetByKey(hEngine, &WFP_PROVIDER_NET_PROC_CONTROL, &provider);
	if (error != ERROR_SUCCESS)
	{
		FWPM_PROVIDER registerProvider{};
		WCHAR name[] = L"EDR POC Firewall";
		registerProvider.displayData.name = name;
		registerProvider.providerKey = WFP_PROVIDER_NET_PROC_CONTROL;
		registerProvider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

		error = FwpmProviderAdd(hEngine, &registerProvider, NULL);
	}
	else {
		FwpmFreeMemory((void**)&provider);
	}

	FwpmEngineClose(hEngine);
	return error;
}

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

void BlockCalc(PHANDLE hpEngine)
{

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

	

	FwpmFilterAdd(hpEngine, &filter, NULL, NULL);

	filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
	FwpmFilterAdd(hpEngine, &filter, NULL, NULL);

	FwpmFreeMemory((void**)&appId);
}

DWORD AddProvider()
{
	// Open engine
	HANDLE hEngine;
	FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

	// Add provider to make it easier to identify filter
	DWORD error = 0;
	FWPM_PROVIDER* provider;
	error = FwpmProviderGetByKey(hEngine, &WFP_PROVIDER_NET_PROC_CONTROL, &provider);
	// If provider not already exists, create it
	if (error != ERROR_SUCCESS) 
	{
		FWPM_PROVIDER reg{};
		WCHAR name[] = L"EDR POC NET PROC CONTROL";
		reg.displayData.name = name;
		reg.providerKey = WFP_PROVIDER_NET_PROC_CONTROL;
		reg.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

		error = FwpmProviderAdd(hEngine, &reg, NULL);
	}
	else {
		FwpmFreeMemory((void**)&provider);
	}
	FwpmEngineClose(hEngine);

	return error;
}

bool AddCallOuts()
{
	HANDLE hEngine;

	DWORD error = FwpmEngineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &hEngine);
	if (error)
		return false;

	do {

		// Create list of callout parameters <Callout GUID, Layer Guid>
		const struct {
			const GUID* guid;
			const GUID* layer;
		} callouts[] = {
		{ &GUID_CALLOUT_PROCESS_BLOCK_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4 },
		{ &GUID_CALLOUT_PROCESS_BLOCK_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6 },
		{ &GUID_CALLOUT_PROCESS_BLOCK_UDP_V4, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4 },
		{ &GUID_CALLOUT_PROCESS_BLOCK_UDP_V6, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6 },
		};

		error = FwpmTransactionBegin(hEngine, 0);
		if (error)
			break;

		// For each pair of callout GUID and layer GUID
		// 1. Create the callout structure
		// 2. Add the callout to the layer
		// 3. Create a filter which will use this callout
		// 4. Add the filter to the layer
		for (auto& co : callouts)
		{
			// Create the callout
			FWPM_CALLOUT callout{};
			callout.applicableLayer = *co.layer;
			callout.calloutKey = *co.guid;
			WCHAR name[] = L"EDR POC Block PID callout";
			callout.displayData.name = name;
			callout.providerKey = (GUID*)&WFP_PROVIDER_NET_PROC_CONTROL;
			FwpmCalloutAdd(hEngine, &callout, nullptr, nullptr);

			// Now add a filter that uses this callout
			FWPM_FILTER filter{};
			filter.layerKey = *co.layer;
			filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
			filter.action.calloutKey = *co.guid;  // Reference to our callout
			WCHAR filterName[] = L"EDR POC Block PID filter";
			filter.displayData.name = filterName;
			filter.providerKey = (GUID*)&WFP_PROVIDER_NET_PROC_CONTROL;
			filter.weight.type = FWP_UINT8;  // Give this a higher weight
			filter.weight.uint8 = 15;        // Higher weight means higher priority
			filter.numFilterConditions = 0;  // No conditions means match all traffic

			error = FwpmFilterAdd(hEngine, &filter, nullptr, nullptr);
			if (error != ERROR_SUCCESS) {
				printf("Failed to add filter: 0x%08X\n", error);
			}

		}

		error = FwpmTransactionCommit(hEngine);
		if (error != ERROR_SUCCESS) {
			printf("Failed to commit transaction: 0x%08X\n", error);
			FwpmTransactionAbort(hEngine);
		}

	} while (false);


	FwpmEngineClose(hEngine);


	return error == ERROR_SUCCESS;
}

#define BLOCK_CMD  "Block"
#define PERMIT_CMD  "Permit"
#define CLEAR_CMD  "Clear"
#define ISOLATE_CMD  "Isolate"
#define UNISOLATE_CMD  "UnIsolate"

int main(int argc, const char* argv[])
{
	//printf("WFP enumeration\n");

	if (argc < 2)
	{
		printf("Usage: NetBlockProc [Block | Permit | Clear | Isolate | UnIsolate] [Process Id] \n");
		return 0;
	}

	const char* command = argv[1];


	HANDLE hDevice = CreateFile(L"\\\\.\\ProcNetFilter", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Error opening device %u\n", GetLastError());
		return 1;
	}

	DWORD error;
	if ((error = AddProvider()) != ERROR_SUCCESS) {
		printf("Error creating the provider: %lu", error);
		return error;
	}


	if (!AddCallOuts()) {
		printf("Error adding callouts\n");
		return 1;
	}

	DWORD returned = 0;
	printf("command: %s\n", command);
	if (strcmp(command, BLOCK_CMD) == 0)
	{
		ULONG pid = atoi(argv[2]);
		printf("Blocking pid %lu", pid);
		DeviceIoControl(hDevice, IOCTL_PNF_BLOCK_PROCESS, &pid, sizeof(ULONG), NULL, 0, &returned, NULL);
	}
	else if (strcmp(command, PERMIT_CMD) == 0)
	{
		ULONG pid = atoi(argv[2]);
		printf("Permitting pid %lu", pid);
		DeviceIoControl(hDevice, IOCTL_PNF_PERMIT_PROCESS, &pid, sizeof(ULONG), NULL, 0, &returned, NULL);

	}
	else if (strcmp(command, CLEAR_CMD) == 0)
	{
		printf("Clearing");
		DeviceIoControl(hDevice, IOCTL_PNF_CLEAR, NULL, 0, NULL, 0, &returned, NULL);

	}
	else if (strcmp(command, ISOLATE_CMD) == 0)
	{
		printf("Isolating");
		DeviceIoControl(hDevice, IOCTL_PNF_ISOLATE, NULL, 0, NULL, 0, &returned, NULL);

	}
	else if (strcmp(command, UNISOLATE_CMD) == 0)
	{
		printf("Releasing Isolation");
		DeviceIoControl(hDevice, IOCTL_PNF_UNISOLATE, NULL, 0, NULL, 0, &returned, NULL);

	}
	return 0;

}