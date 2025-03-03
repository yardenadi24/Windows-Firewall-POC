#pragma once
#include <ntddk.h>

// Test callout guid

// Prototype

typedef struct FWPS_CALLOUT_ {
	GUID calloutKey;
	UINT32 flags;
	FWPS_CALLOUT_CLASSIFY_FN classifyFn;
	FWPS_CALLOUT_NOTIFY_FN notifyFn;
	FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteFn;
} FWPS_CALLOUT;

typedef struct FWPS_INCOMING_VALUE_ {
	FWP_VALUE value;
} FWPS_INCOMING_VALUE;
typedef struct FWPS_INCOMING_VALUES_ {
	UINT16 layerId;
	UINT32 valueCount;
	FWPS_INCOMING_VALUE* incomingValue;
} FWPS_INCOMING_VALUES;

extern 
NTSTATUS
FwpsCalloutRegister(
	_Inout_ void* deviceObject,
	_In_ const FWPS_CALLOUT* callout,
	_Out_opt_ UINT32* calloutId);


void ClassifyFunction(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut);
