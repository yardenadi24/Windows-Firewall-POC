#include <ntddk.h>
#include <fwpsk.h>
#include "common.h"
#include "kutils.h"

#define DEVICE_NAME L"\\Device\\ProcNetFilter"
#define SYM_LINK_NAME L"\\??\\ProcNetFilter"

#define DRIVER_PREFIX "ProcNetFilter: "

#define LOGS(s, ...) DbgPrint(DRIVER_PREFIX "%s::" s "\n", __FUNCTION__, __VA_ARGS__)

NTSTATUS RegisterCallouts(PDEVICE_OBJECT pDeviceObj);
NTSTATUS CompleteIoRequest(PIRP pIrp, NTSTATUS Status = STATUS_SUCCESS, ULONG_PTR Info = 0);
NTSTATUS ProcNetFilterDeviceControl(PDEVICE_OBJECT, PIRP Irp);

PPROCESS_LIST g_pProcessList;

extern "C"
NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymLinkName;
	PDEVICE_OBJECT pDeviceObj;

	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	RtlInitUnicodeString(&SymLinkName, SYM_LINK_NAME);

	BOOLEAN SymLinkCreated = FALSE;

	do {

		Status = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObj);
		if (!NT_SUCCESS(Status))
		{
			LOGS("Failed creating device: 0x%X", Status);
			break;
		}

		Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
		if (!NT_SUCCESS(Status))
		{
			LOGS("Failed creating Symlink: 0x%X", Status);
			break;
		}

		SymLinkCreated = TRUE;

		Status = RegisterCallouts(pDeviceObj);
		if (!NT_SUCCESS(Status))
		{
			LOGS("Failed register callouts: 0x%X", Status);
			break;
		}

		g_pProcessList = ProcessListCreate();
		if (g_pProcessList == NULL)
		{
			LOG("Failed to create the process list");
			break;
		}

		if (!g_pProcessList->Initialized)
		{
			LOG("Failed to initialize the process list");
			break;
		}

	} while (false);

	if (!NT_SUCCESS(Status) || !g_pProcessList || !g_pProcessList->Initialized)
	{
		LOGS("Failed loading driver");
		if (pDeviceObj)
			IoDeleteDevice(pDeviceObj);
		if (SymLinkCreated)
			IoDeleteSymbolicLink(&SymLinkName);
		if (g_pProcessList)
		{
			g_pProcessList->Destroy(g_pProcessList);
		}
	}

	pDriverObject->DriverUnload = ProcNetFilterUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = ProcNetFilterCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcNetFilterCreateClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ProcNetFilterDeviceControl;


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
	NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;
	auto IrpSp = IoGetCurrentIrpStackLocation(pIrp);
	auto const& dic = IrpSp->Parameters.DeviceIoControl;
	ULONG Info = 0;

	switch (dic.IoControlCode)
	{
		case IOCTL_PNF_BLOCK_PROCESS:
		{
			// Add process to process list

			break;
		}
		case IOCTL_PNF_PERMIT_PROCESS:
		{
			// Remove process from process list
			break;
		}
		case IOCTL_PNF_CLEAR:
		{
			// Clear process list
			break;
		}
		default:
			break;
	}
}

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
		// For each Guid we want to create a calllout and register it.
		FWPS_CALLOUT Callout{};
		Callout.calloutKey = *Guid; // Set the key as the GUID
		Callout.notifyFn = OnCalloutNotify; // Set the fn which will be called on notification
		Callout.classifyFn = OnCalloutClassify; // Set the fn which will be called on calssification
		Status |= FwpsCalloutRegister(pDeviceObj, &Callout, NULL);
	}
}

