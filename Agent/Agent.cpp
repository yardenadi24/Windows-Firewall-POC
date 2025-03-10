// Agent.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <string>
#include <TlHelp32.h>
#include "..\FirewallDrv\common.h"

#pragma comment(lib, "Fwpuclnt")

// Command definitions
#define BLOCK_CMD    "Block"
#define PERMIT_CMD   "Permit"
#define CLEAR_CMD    "Clear"
#define ISOLATE_CMD  "Isolate"
#define UNISOLATE_CMD "UnIsolate"

// Get process name from PID for better user feedback
std::wstring GetProcessNameFromPid(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return L"Unknown";
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return pe32.szExeFile;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return L"Unknown";
}

void PrintUsage() {
    printf("\n+==================================================+\n");
    printf("|            Process Network Firewall              |\n");
    printf("+==================================================+\n\n");
    printf("Usage: Agent [Block | Permit | Clear | Isolate | UnIsolate] [Process Id]\n\n");
    printf("Commands:\n");
    printf("  Block <pid>     - Block network access for the specified process\n");
    printf("  Permit <pid>    - Allow network access for the specified process\n");
    printf("  Clear           - Clear all process rules\n");
    printf("  Isolate         - Enable network isolation mode\n");
    printf("  UnIsolate       - Disable network isolation mode\n\n");
    printf("Examples:\n");
    printf("  Agent Block 1234     - Block process with PID 1234\n");
    printf("  Agent Permit 5678    - Allow process with PID 5678\n");
    printf("  Agent Isolate        - Enable network isolation\n\n");
}

DWORD RegisterProviders() {
    HANDLE hEngine;
    DWORD error = FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    if (error) {
        return error;
    }

    FWPM_PROVIDER* provider;
    error = FwpmProviderGetByKey(hEngine, &WFP_PROVIDER_NET_PROC_CONTROL, &provider);
    if (error != ERROR_SUCCESS) {
        FWPM_PROVIDER registerProvider{};
        // Using wcscpy_s to handle const correctness issues
        wchar_t name[100] = L"EDR POC Firewall";
        wcscpy_s(registerProvider.displayData.name, _countof(name), name);
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

std::wstring GuidToString(GUID const& guid) {
    WCHAR sGuid[64];
    return ::StringFromGUID2(guid, sGuid, _countof(sGuid)) ? sGuid : L"";
}

const char* ActionToString(FWPM_ACTION const& action) {
    switch (action.type) {
    case FWP_ACTION_BLOCK:                 return "Block";
    case FWP_ACTION_PERMIT:                return "Permit";
    case FWP_ACTION_CALLOUT_TERMINATING:   return "Callout Terminating";
    case FWP_ACTION_CALLOUT_INSPECTION:    return "Callout Inspection";
    case FWP_ACTION_CALLOUT_UNKNOWN:       return "Callout Unknown";
    case FWP_ACTION_CONTINUE:              return "Continue";
    case FWP_ACTION_NONE:                  return "None";
    case FWP_ACTION_NONE_NO_MATCH:         return "None (No Match)";
    }
    return "";
}

void EnumFilters(PHANDLE hpEngine) {
    HANDLE hEnum;
    HANDLE hEngine = *hpEngine;
    FwpmFilterCreateEnumHandle(hEngine, NULL, &hEnum);

    UINT32 count;
    FWPM_FILTER** filters;
    FwpmFilterEnum(hEngine, hEnum, 8192 /*Max entries*/, &filters/*Returned results*/, &count /*How many we got*/);

    printf("\n+==================================================+\n");
    printf("|               Active WFP Filters                 |\n");
    printf("+==================================================+\n\n");

    printf("%-5s %-40s %-15s %-10s\n", "ID", "Name", "Conditions", "Action");
    printf("---------------------------------------------------------------------\n");

    for (UINT32 i = 0; i < count; i++) {
        auto f = filters[i];
        // Only show our provider's filters to avoid cluttering the output
        if (f->providerKey && IsEqualGUID(*f->providerKey, WFP_PROVIDER_NET_PROC_CONTROL)) {
            printf("%5d %-40ws %-15d %-10s\n",
                f->filterId,
                f->displayData.name,
                f->numFilterConditions,
                ActionToString(f->action));
        }
    }
    printf("\n");

    FwpmFreeMemory((void**)&filters);
    FwpmFilterDestroyEnumHandle(hEngine, hEnum);
}

void BlockCalc(PHANDLE hpEngine) {
    FWPM_FILTER filter{};
    // Use a non-const copy of the string
    wchar_t filterName[100];
    wcscpy_s(filterName, L"Prevent Calculator from accessing the web");
    filter.displayData.name = filterName;

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.action.type = FWP_ACTION_BLOCK;

    WCHAR filename[MAX_PATH];
    wcscpy_s(filename, LR"(C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_11.2411.1.0_x64__8wekyb3d8bbwe\CalculatorApp.exe)");
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

DWORD AddProvider() {
    // Open engine
    HANDLE hEngine;
    FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);

    // Add provider to make it easier to identify filter
    DWORD error = 0;
    FWPM_PROVIDER* provider;
    error = FwpmProviderGetByKey(hEngine, &WFP_PROVIDER_NET_PROC_CONTROL, &provider);
    // If provider not already exists, create it
    if (error != ERROR_SUCCESS) {
        FWPM_PROVIDER reg{};
        wchar_t name[100];
        wcscpy_s(name, L"EDR POC NET PROC CONTROL");
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

bool AddCallOuts() {
    HANDLE hEngine;

    DWORD error = FwpmEngineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, nullptr, &hEngine);
    if (error)
        return false;

    do {
        // Create list of callout parameters <Callout GUID, Layer Guid>
        const struct {
            const GUID* guid;
            const GUID* layer;
            const wchar_t* name;
        } callouts[] = {
            { &GUID_CALLOUT_PROCESS_BLOCK_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, L"TCP IPv4 Process Block" },
            { &GUID_CALLOUT_PROCESS_BLOCK_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, L"TCP IPv6 Process Block" },
            { &GUID_CALLOUT_PROCESS_BLOCK_UDP_V4, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, L"UDP IPv4 Process Block" },
            { &GUID_CALLOUT_PROCESS_BLOCK_UDP_V6, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, L"UDP IPv6 Process Block" },
        };

        error = FwpmTransactionBegin(hEngine, 0);
        if (error)
            break;

        // For each pair of callout GUID and layer GUID
        for (auto& co : callouts) {
            // Create the callout
            FWPM_CALLOUT callout{};
            callout.applicableLayer = *co.layer;
            callout.calloutKey = *co.guid;

            // Create a non-const copy of the name
            wchar_t calloutName[100];
            wcscpy_s(calloutName, co.name);
            callout.displayData.name = calloutName;

            callout.providerKey = (GUID*)&WFP_PROVIDER_NET_PROC_CONTROL;
            FwpmCalloutAdd(hEngine, &callout, nullptr, nullptr);

            // Now add a filter that uses this callout
            FWPM_FILTER filter{};
            filter.layerKey = *co.layer;
            filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
            filter.action.calloutKey = *co.guid;  // Reference to our callout

            wchar_t filterName[100];
            swprintf_s(filterName, L"EDR POC Filter for %s", calloutName);
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

int main(int argc, const char* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    const char* command = argv[1];

    // Open the device with a better error message
    HANDLE hDevice = CreateFile(L"\\\\.\\ProcNetFilter", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("\n[ERROR] Could not connect to firewall driver (Error %u)\n", GetLastError());
        printf("Make sure the driver service is installed and running.\n\n");
        return 1;
    }

    // Add provider with better feedback
    DWORD error;
    if ((error = AddProvider()) != ERROR_SUCCESS && error != FWP_E_ALREADY_EXISTS) {
        printf("\n[ERROR] Failed to register with Windows Filtering Platform (%lu)\n", error);
        printf("Some functionality may not work correctly.\n\n");
    }

    // Add callouts with better feedback
    if (!AddCallOuts()) {
        printf("\n[WARNING] Firewall callout registration incomplete.\n");
        printf("The firewall will continue to function with limited capabilities.\n\n");
    }

    DWORD returned = 0;

    // Process commands with improved UI
    if (_stricmp(command, BLOCK_CMD) == 0) {
        if (argc < 3) {
            printf("\n[ERROR] Missing process ID parameter.\n");
            PrintUsage();
            CloseHandle(hDevice);
            return 1;
        }

        ULONG pid = atoi(argv[2]);
        std::wstring procName = GetProcessNameFromPid(pid);

        printf("\n[BLOCK] Blocking network access for process: %ws (PID: %lu)\n", procName.c_str(), pid);

        if (DeviceIoControl(hDevice, IOCTL_PNF_BLOCK_PROCESS, &pid, sizeof(ULONG), NULL, 0, &returned, NULL)) {
            printf("[SUCCESS] Network access blocked successfully!\n\n");
        }
        else {
            printf("[FAILED] Failed to block network access (Error: %lu)\n\n", GetLastError());
        }
    }
    else if (_stricmp(command, PERMIT_CMD) == 0) {
        if (argc < 3) {
            printf("\n[ERROR] Missing process ID parameter.\n");
            PrintUsage();
            CloseHandle(hDevice);
            return 1;
        }

        ULONG pid = atoi(argv[2]);
        std::wstring procName = GetProcessNameFromPid(pid);

        printf("\n[PERMIT] Allowing network access for process: %ws (PID: %lu)\n", procName.c_str(), pid);

        if (DeviceIoControl(hDevice, IOCTL_PNF_PERMIT_PROCESS, &pid, sizeof(ULONG), NULL, 0, &returned, NULL)) {
            printf("[SUCCESS] Network access permitted successfully!\n\n");
        }
        else {
            printf("[FAILED] Failed to permit network access (Error: %lu)\n\n", GetLastError());
        }
    }
    else if (_stricmp(command, CLEAR_CMD) == 0) {
        printf("\n[CLEAR] Clearing all process network rules...\n");

        if (DeviceIoControl(hDevice, IOCTL_PNF_CLEAR, NULL, 0, NULL, 0, &returned, NULL)) {
            printf("[SUCCESS] All process rules cleared successfully!\n\n");
        }
        else {
            printf("[FAILED] Failed to clear process rules (Error: %lu)\n\n", GetLastError());
        }
    }
    else if (_stricmp(command, ISOLATE_CMD) == 0) {
        printf("\n[ISOLATE] Enabling network isolation mode...\n");

        if (DeviceIoControl(hDevice, IOCTL_PNF_ISOLATE, NULL, 0, NULL, 0, &returned, NULL)) {
            printf("[SUCCESS] Network isolation enabled successfully!\n");
            printf("[INFO] The system is now isolated from network connections except for permitted processes.\n\n");
        }
        else {
            printf("[FAILED] Failed to enable isolation mode (Error: %lu)\n\n", GetLastError());
        }
    }
    else if (_stricmp(command, UNISOLATE_CMD) == 0) {
        printf("\n[UNISOLATE] Disabling network isolation mode...\n");

        if (DeviceIoControl(hDevice, IOCTL_PNF_UNISOLATE, NULL, 0, NULL, 0, &returned, NULL)) {
            printf("[SUCCESS] Network isolation disabled successfully!\n");
            printf("[INFO] Normal network connectivity restored.\n\n");
        }
        else {
            printf("[FAILED] Failed to disable isolation mode (Error: %lu)\n\n", GetLastError());
        }
    }
    else if (_stricmp(command, "help") == 0 || _stricmp(command, "--help") == 0 || _stricmp(command, "-h") == 0) {
        // Additional help command
        PrintUsage();
    }
    else if (_stricmp(command, "status") == 0 || _stricmp(command, "--status") == 0) {
        // New status command to show WFP filters
        HANDLE hEngine;
        FwpmEngineOpen(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
        EnumFilters(&hEngine);
        FwpmEngineClose(hEngine);
    }
    else {
        printf("\n[ERROR] Unknown command: %s\n", command);
        PrintUsage();
    }

    CloseHandle(hDevice);
    return 0;
}