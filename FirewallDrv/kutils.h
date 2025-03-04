#pragma once
#include <ntddk.h>

#define MODULE_PREFIX "kUtils"
#define LOG(s, ...) DbgPrint(MODULE_PREFIX "%s::" s "\n", __FUNCTION__, __VA_ARGS__)

// ----------------------- // PROCESS LIST // ----------------------- //

#define PROCESS_LIST_TAG 'tslP'


typedef struct _PROCESS_LIST PROCESS_LIST, * PPROCESS_LIST;
typedef NTSTATUS (*PFN_PROCESS_LIST_ADD) (IN PPROCESS_LIST List, IN HANDLE ProcessId);
typedef NTSTATUS(*PFN_PROCESS_LIST_REMOVE)(IN PPROCESS_LIST List, IN HANDLE ProcessId);
typedef NTSTATUS(*PFN_PROCESS_LIST_CLEAR)(IN PPROCESS_LIST List);
typedef BOOLEAN(*PFN_PROCESS_LIST_CONTAINSE)(IN PPROCESS_LIST List, IN HANDLE ProcessId);
typedef VOID(*PFN_PROCESS_LIST_PRINT)(IN PPROCESS_LIST List);
typedef VOID(*PFN_PROCESS_LIST_DESTROY)(IN PPROCESS_LIST List);

typedef struct _PROCESS_ENTRY
{
	LIST_ENTRY Link;
	HANDLE ProcessId;
} PROCESS_ENTRY, *PPROCESS_ENTRY;

typedef struct _PROCESS_LIST
{

	LIST_ENTRY ListHead;
	KSPIN_LOCK Lock;
	BOOLEAN Initialized;

	// Methods
	PFN_PROCESS_LIST_ADD Add;
	PFN_PROCESS_LIST_REMOVE Remove;
	PFN_PROCESS_LIST_CONTAINSE Contains;
	PFN_PROCESS_LIST_PRINT Print;
	PFN_PROCESS_LIST_CLEAR Clear;
	PFN_PROCESS_LIST_DESTROY Destroy;



} PROCESS_LIST, *PPROCESS_LIST;

// Function prototypes (internal implementation)
NTSTATUS ProcessListAdd(IN PPROCESS_LIST List, IN HANDLE ProcessId);
NTSTATUS ProcessListRemove(IN PPROCESS_LIST List, IN HANDLE ProcessId);
NTSTATUS ProcessListClear(IN PPROCESS_LIST List);
BOOLEAN ProcessListContains(IN PPROCESS_LIST List, IN HANDLE ProcessId);
VOID ProcessListPrint(IN PPROCESS_LIST List);
VOID ProcessListDestroy(IN PPROCESS_LIST List);


// Constructor: Create and initialize a new process list
PPROCESS_LIST
ProcessListCreate(VOID)
{
	PPROCESS_LIST pList;

	pList = (PPROCESS_LIST)ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(PROCESS_LIST),
		PROCESS_LIST_TAG
	);

	if (pList == NULL)
	{
		LOG("Failed allocating List");
		return NULL;
	}

	pList->Add = ProcessListAdd;
	pList->Remove = ProcessListRemove;
	pList->Contains = ProcessListContains;
	pList->Print = ProcessListPrint;
	pList->Destroy = ProcessListDestroy;

	pList->Initialized = TRUE;

	return pList;
}

// Clear all entries from the list
NTSTATUS
ProcessListClear(
	IN PPROCESS_LIST pList
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PLIST_ENTRY pEntry;
	PPROCESS_ENTRY pProcessEntry;
	KIRQL oldIrql;
	ULONG Count = 0;

	// Validate list
	if (pList == NULL)
	{
		Status =  STATUS_INVALID_PARAMETER;
		LOG("Failed clearing list, the pList is NULL, 0x%X", Status);
		return Status;
	}

	// Make sure we are initialized
	if (!pList->Initialized)
	{
		Status = STATUS_INVALID_PARAMETER;
		LOG("Failed clearing list, the pList is not initialized, 0x%X", Status);
		return Status;
	}

	// Remove all entries
	KeAcquireSpinLock(&pList->Lock, &oldIrql);

	while (!IsListEmpty(&pList->ListHead))
	{
		pEntry = RemoveHeadList(&pList->ListHead);
		pProcessEntry = CONTAINING_RECORD(pEntry, PROCESS_ENTRY, Link);
		if (pProcessEntry != NULL)
		{
			ExFreePoolWithTag(pProcessEntry, PROCESS_LIST_TAG);
			Count++;
		}

	}
	
	KeReleaseSpinLock(&pList->Lock, oldIrql);
	
	LOG("Cleared &lu processes from the list", Count);
	return Status;
}

// Check if a process ID is in the list
BOOLEAN
ProcessListContains(
	IN PPROCESS_LIST pList,
	IN HANDLE ProcessId
)
{
	PLIST_ENTRY pEntry;
	PPROCESS_ENTRY	pProcessEntry;
	KIRQL oldIrql;
	BOOLEAN found = FALSE;

	// Validate input
	if (pList == NULL || ProcessId == NULL) {
		return FALSE;
	}

	// Make sure we're initialized
	if (!pList->Initialized) {
		return FALSE;
	}

	// Search the list with lock protection
	KeAcquireSpinLock(&pList->Lock, &oldIrql);

	pEntry = pList->ListHead.Flink;
	while (pEntry != &pList->ListHead) {
		pProcessEntry = CONTAINING_RECORD(pEntry, PROCESS_ENTRY, Link);

		if (pProcessEntry->ProcessId == ProcessId) {
			// Found the process
			found = TRUE;
			break;
		}

		pEntry = pEntry->Flink;
	}

	KeReleaseSpinLock(&pList->Lock, oldIrql);

	return found;
}

VOID
ProcessListDestroy(
	IN PPROCESS_LIST List
)
{
	// Validate input
	if (List == NULL) {
		return;
	}

	// Clear all entries from the list
	ProcessListClear(List);

	// Free the list object itself
	ExFreePoolWithTag(List, PROCESS_LIST_TAG);
}


// Remove a process ID from the list
NTSTATUS
ProcessListRemove(
	IN PPROCESS_LIST pList,
	IN HANDLE ProcessId
)
{
	PLIST_ENTRY pEntry;
	PPROCESS_ENTRY pProcessEntry;
	KIRQL oldIrql;
	BOOLEAN found = FALSE;

	// Validate input
	if (pList == NULL || ProcessId == NULL) {
		return STATUS_INVALID_PARAMETER;
	}

	// Make sure we're initialized
	if (!pList->Initialized) {
		return STATUS_INVALID_PARAMETER;
	}

	// Find and remove the entry with lock protection
	KeAcquireSpinLock(&pList->Lock, &oldIrql);

	pEntry = pList->ListHead.Flink;
	while (pEntry != &pList->ListHead) {
		pProcessEntry = CONTAINING_RECORD(pEntry, PROCESS_ENTRY, Link);

		// Save the next entry before potentially removing the current one
		PLIST_ENTRY nextEntry = pEntry->Flink;

		if (pProcessEntry->ProcessId == ProcessId) {
			// Found the process, remove it
			RemoveEntryList(&pProcessEntry->Link);
			ExFreePoolWithTag(pProcessEntry, PROCESS_LIST_TAG);
			found = TRUE;
			break;
		}

		pEntry = nextEntry;
	}

	KeReleaseSpinLock(&pList->Lock, oldIrql);

	if (!found) {
		LOG("Process ID %llu not found in list\n", (ULONG64)ProcessId);
		return STATUS_NOT_FOUND;
	}

	LOG("Removed Process ID %llu from list\n", (ULONG64)ProcessId);
	return STATUS_SUCCESS;
}

// Print all processes in the list (for debugging)
VOID
ProcessListPrint(
	IN PPROCESS_LIST pList
)
{
	PLIST_ENTRY pEntry;
	PPROCESS_ENTRY pProcessEntry;
	KIRQL oldIrql;
	ULONG count = 0;

	// Validate input
	if (pList == NULL) {
		DbgPrint("Invalid process list pointer\n");
		return;
	}

	// Make sure we're initialized
	if (!pList->Initialized) {
		DbgPrint("Process list not initialized\n");
		return;
	}

	// Print all entries with lock protection
	KeAcquireSpinLock(&pList->Lock, &oldIrql);

	DbgPrint("Process List Contents:\n");
	DbgPrint("---------------------\n");

	pEntry = pList->ListHead.Flink;
	while (pEntry != &pList->ListHead) {
		pProcessEntry = CONTAINING_RECORD(pEntry, PROCESS_ENTRY, Link);
		DbgPrint("[%03lu] Process ID: %llu\n", count, (ULONG64)pProcessEntry->ProcessId);
		pEntry = pEntry->Flink;
		count++;
	}

	if (count == 0) {
		DbgPrint("(List is empty)\n");
	}

	DbgPrint("Total: %lu processes\n", count);

	KeReleaseSpinLock(&pList->Lock, oldIrql);
}

// Add a process ID to the list
NTSTATUS
ProcessListAdd(
	IN PPROCESS_LIST pList,
	IN HANDLE ProcessId
)
{
	PPROCESS_ENTRY pEntry;
	KIRQL oldIrql;

	// Validate input
	if (pList == NULL || ProcessId == NULL) {
		return STATUS_INVALID_PARAMETER;
	}

	// Make sure we're initialized
	if (!pList->Initialized) {
		return STATUS_INVALID_PARAMETER;
	}

	// Check if process is already in the list (optional)
	if (ProcessListContains(pList, ProcessId)) {
		LOG("Process ID %llu already in list\n", (ULONG64)ProcessId);
		return STATUS_DUPLICATE_OBJECTID;
	}

	// Allocate memory for the entry
	pEntry = (PPROCESS_ENTRY)ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(PROCESS_ENTRY),
		PROCESS_LIST_TAG
	);

	if (pEntry == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Initialize the entry
	pEntry->ProcessId = ProcessId;

	// Add the entry to the list with lock protection
	KeAcquireSpinLock(&pList->Lock, &oldIrql);
	InsertTailList(&pList->ListHead, &pEntry->Link);
	KeReleaseSpinLock(&pList->Lock, oldIrql);

	LOG("Added Process ID %llu to list\n", (ULONG64)ProcessId);
	return STATUS_SUCCESS;
}
