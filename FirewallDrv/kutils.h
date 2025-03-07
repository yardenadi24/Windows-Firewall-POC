#pragma once
#include <ntifs.h>

#pragma warning(disable: 4996)

#define MODULE_PREFIX "KUtils "
#define LOGu(s, ...) DbgPrint(MODULE_PREFIX "::%s:: " s "\n",__FUNCTION__,__VA_ARGS__)

#define PROCESS_LIST_TAG 'tslP'

// Global operator new and delete for kernel-mode
void* __cdecl operator new(size_t size) {
	return ExAllocatePoolWithTag(NonPagedPool, size, PROCESS_LIST_TAG);
}

void __cdecl operator delete(void* p) {
	if (p) {
		ExFreePoolWithTag(p, PROCESS_LIST_TAG);
	}
}

// Sized delete operator - needed for classes with virtual destructors or when using certain compiler options
void __cdecl operator delete(void* p, size_t size) {
	UNREFERENCED_PARAMETER(size);  // We don't use the size parameter
	if (p) {
		ExFreePoolWithTag(p, PROCESS_LIST_TAG);
	}
}

typedef struct _LOCK
{
	PKSPIN_LOCK m_pLock;
	KIRQL m_OldIrql;

	_LOCK(PKSPIN_LOCK pLock) : m_pLock(pLock)
	{
		KeAcquireSpinLock(m_pLock, &m_OldIrql);
	}

	~_LOCK()
	{
		KeReleaseSpinLock(m_pLock, m_OldIrql);
	}

}LOCK, * PLOCK;


typedef struct _PROCESS_ENTRY
{
	LIST_ENTRY m_Link;
	ULONG m_ProcessId;

	// Constructor
	_PROCESS_ENTRY(ULONG ProcessId) : m_ProcessId(ProcessId) {}

	// Destructor
	~_PROCESS_ENTRY() = default;


}PROCESS_ENTRY, * PPROCESS_ENTRY;


// Helper method to to get _PROCESS_ENTRY out of the LIST_ENTRY
PPROCESS_ENTRY ProcessFromListEntry(PLIST_ENTRY pListEntry)
{
	return CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, m_Link);
}


typedef struct _PROCESS_LIST
{
	
	LIST_ENTRY m_ListHead;
	KSPIN_LOCK m_Lock;
	BOOLEAN m_Initialized = FALSE;

	// Construct
	_PROCESS_LIST()
	{
		InitializeListHead(&m_ListHead);
		KeInitializeSpinLock(&m_Lock);
		m_Initialized = TRUE;
	}

	// Destructor
	~_PROCESS_LIST()
	{
		Clear();
	}

	NTSTATUS Clear()
	{
		ULONG Count = 0;
		ULONG Total = 0;

		{
			LOCK TempLock(&m_Lock);

			while (!IsListEmpty(&m_ListHead))
			{
				Total++;
				PLIST_ENTRY pEntry = RemoveHeadList(&m_ListHead);
				PPROCESS_ENTRY pProcessEntry = ProcessFromListEntry(pEntry);
				if (pProcessEntry != NULL)
				{
					delete pProcessEntry;
					Count++;
				}
			}
		}

		LOGu("Removed %lu out of %lu entries from the list", Count, Total);
		if (Total != Count)
			return STATUS_UNSUCCESSFUL;
		else
			return STATUS_SUCCESS;
	}

	BOOLEAN Contains(ULONG Pid)
	{
		if (Pid == 0)
		{
			LOGu("Pid is 0, invalid");
			return FALSE;
		}

		BOOLEAN Found = FALSE;

		// Scope the lock
		{
			LOCK TempLock(&m_Lock);

			for (PLIST_ENTRY pEntry = m_ListHead.Flink;
				pEntry != &m_ListHead;
				pEntry = pEntry->Flink)
			{
				PPROCESS_ENTRY pProcessEntry = ProcessFromListEntry(pEntry);
				
				if (pProcessEntry->m_ProcessId == Pid)
				{
					LOGu("Found entry with Pid: (%lu)");
					Found = TRUE;
					break;
				}
			}

		}

		return Found;
	}

	NTSTATUS Add(ULONG Pid)
	{
		if (Pid == 0)
		{
			LOGu("Pid is 0, invalid");
			return STATUS_INVALID_PARAMETER;
		}

		if (Contains(Pid))
		{
			LOGu("Pid already exists. (%lu)", Pid);
			return STATUS_DUPLICATE_OBJECTID;
		}

		// Add PROCESS_ENTRY
		PPROCESS_ENTRY pEntry = NULL;
		pEntry = new PROCESS_ENTRY(Pid);

		if (pEntry == NULL)
		{
			LOGu("Failed creating PROCESS_ENTRY from pid(%lu)", Pid);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		{
			LOCK TempLock(&m_Lock);
			InsertTailList(&m_ListHead, &pEntry->m_Link);
		}

		LOGu("Added process pid(%lu) to the list");
		return STATUS_SUCCESS;
	}

	NTSTATUS Remove(ULONG Pid)
	{
		if (Pid == 0)
		{
			LOGu("Pid is 0, invalid");
			return STATUS_INVALID_PARAMETER;
		}

		BOOLEAN Found = FALSE;
		{
			LOCK TempLock(&m_Lock);

			for (PLIST_ENTRY pEntry = m_ListHead.Flink; pEntry != &m_ListHead; pEntry = pEntry->Flink)
			{
				PPROCESS_ENTRY pProcessEntry = ProcessFromListEntry(pEntry);

				if (pProcessEntry->m_ProcessId == Pid)
				{
					LOGu("Found process pid(%lu), removing entry ...", Pid);
					RemoveEntryList(pEntry);
					delete pProcessEntry;
					Found = TRUE;
					break;
				}
			}
		}

		if (!Found)
		{
			LOGu("Process pid(%lu) not found in list", Pid);
			return STATUS_NOT_FOUND;
		}

		LOGu("Removed Process PID %lu from list", Pid);
		return STATUS_SUCCESS;
	}

}PROCESS_LIST, *PPROCESS_LIST
;

