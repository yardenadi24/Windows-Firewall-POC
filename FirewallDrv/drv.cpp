// First, define NDIS version before including any headers
#define NDIS_SUPPORT_NDIS6 1
#define NDIS630 1

// WDF headers - use KMDF for kernel mode
#include <ntifs.h>

// Network headers - order is important
#include <ndis.h>
#include <netioapi.h>
#include <ntintsafe.h>

// IP definitions
#include <ws2def.h>
#include <ws2ipdef.h>
#include <inaddr.h>
#include <in6addr.h>
#include <ip2string.h>

// WFP headers - these must come after all the above
#include <fwpmk.h>
#include <fwpsk.h>
#include <fwpvi.h>

// Your custom headers
#include "kutils.h"
#include "common.h"

#define DEVICE_NAME L"\\Device\\ProcNetFilter"
#define SYM_LINK_NAME L"\\??\\ProcNetFilter"

#define DRIVER_PREFIX "ProcNetFilter: "

#define LOG(s, ...) DbgPrint(DRIVER_PREFIX "%s::" s "\n", __FUNCTION__, __VA_ARGS__)

NTSTATUS RegisterCallouts(PDEVICE_OBJECT pDeviceObj);
NTSTATUS CompleteIoRequest(PIRP pIrp, NTSTATUS Status = STATUS_SUCCESS, ULONG_PTR Info = 0);
NTSTATUS ProcNetFilterDeviceControl(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS OnCalloutNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID* filterKey, FWPS_FILTER* filter);
void OnCalloutClassify(const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData, const void* classifyContext, const FWPS_FILTER* filter,
	UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
NTSTATUS ProcNetFilterCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
VOID ProcNetFilterUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS UnregisterCallouts();

PPROCESS_LIST g_pProcessList;
BOOLEAN g_BlockAll;

extern "C"
NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymLinkName;
	PDEVICE_OBJECT pDeviceObj;

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&SymLinkName, SYM_LINK_NAME);

	BOOLEAN SymLinkCreated = FALSE;
	g_BlockAll = FALSE;

	do {

		Status = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObj);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed creating device: 0x%X", Status);
			break;
		}

		Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed creating Symlink: 0x%X", Status);
			break;
		}

		SymLinkCreated = TRUE;

		Status = RegisterCallouts(pDeviceObj);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed register callouts: 0x%X", Status);
			break;
		}

		g_pProcessList = new PROCESS_LIST();
		if (g_pProcessList == NULL)
		{
			LOG("Failed to create the process list");
			break;
		}

		if (!g_pProcessList->m_Initialized)
		{
			LOG("Failed to initialize the process list");
			break;
		}

	} while (false);

	if (!NT_SUCCESS(Status) || !g_pProcessList || !g_pProcessList->m_Initialized)
	{
		LOG("Failed loading driver");
		if (pDeviceObj)
			IoDeleteDevice(pDeviceObj);
		if (SymLinkCreated)
			IoDeleteSymbolicLink(&SymLinkName);
		if (g_pProcessList)
		{
			delete g_pProcessList;
			g_pProcessList = NULL;
		}
	}

	pDriverObject->DriverUnload = ProcNetFilterUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = ProcNetFilterCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcNetFilterCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcNetFilterDeviceControl;

	LOG("Finished driver entry with code: 0x%X", Status);

	return Status;
}



NTSTATUS
OnCalloutNotify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID* filterKey,
	FWPS_FILTER* filter)
{
	UNREFERENCED_PARAMETER(filter);

	UNICODE_STRING sGuid = RTL_CONSTANT_STRING(L"<Noguid>");
	
	if (filterKey)
		RtlStringFromGUID(*filterKey, &sGuid);
	
	if (notifyType == FWPS_CALLOUT_NOTIFY_ADD_FILTER)
		LOG("Filter added %wZ", sGuid);
	else if (notifyType == FWPS_CALLOUT_NOTIFY_DELETE_FILTER)
		LOG("Filter deleted %wZ", sGuid);

	if (filterKey)
		RtlFreeUnicodeString(&sGuid);
	
	return STATUS_SUCCESS;
}

void OnCalloutClassify(
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut)
{
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(inFixedValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(classifyContext);

	classifyOut->actionType = FWP_ACTION_PERMIT;

	if (g_BlockAll)
	{
		LOG("In isolation mode blocking");
		// Block process
		classifyOut->actionType = FWP_ACTION_BLOCK;

		// Ask other filters to not override the block action
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}

	// Check if PID value is set
	if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0)
		return;

	if (g_pProcessList == NULL || !g_pProcessList->m_Initialized)
		return;

	// Classify is running on IRQL DISPATCH_LEVEL (2)
	// That why we cant use fast mutex and only spin lock

	BOOLEAN Block = g_pProcessList->Contains((ULONG)inMetaValues->processId);
	LOG("Process %lu,  Contains: %lu", (ULONG)inMetaValues->processId, Block);
	if (Block)
	{
		// Block process
		classifyOut->actionType = FWP_ACTION_BLOCK;

		// Ask other filters to not override the block action
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

		LOG("Blocked process %lu", (ULONG)inMetaValues->processId);
	}

}

NTSTATUS UnregisterCallouts()
{
	NTSTATUS Status = STATUS_SUCCESS;

	// Unregister the callouts using the same GUIDs
	CONST GUID* Guids[] =
	{
		&GUID_CALLOUT_PROCESS_BLOCK_V4,
		&GUID_CALLOUT_PROCESS_BLOCK_V6,
		&GUID_CALLOUT_PROCESS_BLOCK_UDP_V4,
		&GUID_CALLOUT_PROCESS_BLOCK_UDP_V6,
	};

	for (auto& Guid : Guids)
	{
		// Unregister each callout
		NTSTATUS tempStatus = FwpsCalloutUnregisterByKey(Guid);
		if (!NT_SUCCESS(tempStatus))
		{
			LOG("Failed to unregister callout with GUID, status: 0x%X", tempStatus);
			Status = tempStatus;
		}
	}

	return Status;
}


NTSTATUS
CompleteIoRequest(
	PIRP pIrp, 
	NTSTATUS Status, 
	ULONG_PTR Info)
{
	pIrp->IoStatus.Status = Status;
	pIrp->IoStatus.Information = Info;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS
ProcNetFilterDeviceControl(
	PDEVICE_OBJECT pDeviceObject,
	PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);

	NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
	auto IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	auto const& dic = IrpSp->Parameters.DeviceIoControl;
	ULONG Info = 0;

	switch (dic.IoControlCode)
	{
	case IOCTL_PNF_BLOCK_PROCESS:
	{
		if (dic.InputBufferLength < sizeof(ULONG))
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		// Add process to process list
		ULONG Pid = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;

		Status = g_pProcessList->Add(Pid);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed adding process to list: %lu (0x%X)", Pid, Status);
		}

		break;
	}
	case IOCTL_PNF_PERMIT_PROCESS:
	{
		if (dic.InputBufferLength < sizeof(ULONG))
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		// Remove process from process list
		ULONG Pid = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;

		Status = g_pProcessList->Remove(Pid);
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed removing process to list: %lu (0x%X)", Pid, Status);
		}

		break;
	}
	case IOCTL_PNF_CLEAR:
	{
		// Clear process list
		Status = g_pProcessList->Clear();
		if (!NT_SUCCESS(Status))
		{
			LOG("Failed removing process to list: (0x%X)", Status);
		}
		break;
	}
	case IOCTL_PNF_ISOLATE:
	{
		g_BlockAll = TRUE;
		LOG("Isolating all from network");
		break;
	}
	case IOCTL_PNF_UNISOLATE:
	{
		g_BlockAll = FALSE;
		LOG("Release isolation from network");
		break;
	}
		default:
			break;
	}

	// Complete the IRP
	return CompleteIoRequest(pIrp, Status, Info);
}

// Register the callouts
NTSTATUS RegisterCallouts(PDEVICE_OBJECT pDeviceObj)
{
	NTSTATUS Status = STATUS_SUCCESS;

	CONST GUID* Guids[] =
	{
		&GUID_CALLOUT_PROCESS_BLOCK_V4,
		&GUID_CALLOUT_PROCESS_BLOCK_V6,
		&GUID_CALLOUT_PROCESS_BLOCK_UDP_V4,
		&GUID_CALLOUT_PROCESS_BLOCK_UDP_V6,
	};

	for (auto& Guid : Guids)
	{
		// For each Guid we want to create a callout and register it.
		FWPS_CALLOUT Callout{};
		Callout.calloutKey = *Guid; // Set the key as the GUID
		Callout.notifyFn = OnCalloutNotify; // Set the fn which will be called on notification
		Callout.classifyFn = OnCalloutClassify; // Set the fn which will be called on classification
		Status |= FwpsCalloutRegister(pDeviceObj, &Callout, NULL);

	}

	return Status;
}

VOID
ProcNetFilterUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UnregisterCallouts();

	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, SYM_LINK_NAME);

	// Delete the symbolic link
	IoDeleteSymbolicLink(&symLinkName);

	// Clean up the process list
	if (g_pProcessList != NULL) {
		delete g_pProcessList;
		g_pProcessList = NULL;
	}

	// Unregister WFP callouts (you should have a function for this)
	// UnregisterCallouts(); // Uncomment if you have this function

	// Delete the device object
	if (DriverObject->DeviceObject != NULL) {
		IoDeleteDevice(DriverObject->DeviceObject);
	}

	LOG("Driver unloaded successfully");
}

NTSTATUS
ProcNetFilterCreateClose(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	// For most filter drivers, we simply complete these requests successfully
	// as they represent a user-mode application opening or closing a handle to our device

	return CompleteIoRequest(Irp, STATUS_SUCCESS);
}