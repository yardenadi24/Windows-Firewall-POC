# Windows Process Network Filtering POC

A proof-of-concept kernel driver and user-mode application demonstrating process-based network filtering using the Windows Filtering Platform (WFP).

## Overview

This project implements a simple but powerful process-based network filtering system consisting of:

1. A kernel-mode driver (`FirewallDrv`) that inspects network traffic
2. A user-mode application (`Agent`) that manages filtering rules

The system allows you to:
- Block specific processes from accessing the network
- Allow previously blocked processes to regain network access
- Clear all filtering rules
- Fully isolate the system (block all network traffic)
- Restore network connectivity after isolation

## WFP Architecture

This project demonstrates key Windows Filtering Platform concepts:

- **Callouts**: Kernel-mode code that inspects network traffic
- **Filters**: Rules that determine when callouts are invoked
- **Layers**: Specific points in the network stack where filters can be applied
- **Providers**: Organizational units that group related filters

The implementation works at both the connection layer (`ALE_AUTH_CONNECT`) and resource assignment layer (`ALE_RESOURCE_ASSIGNMENT`), covering both TCP and UDP traffic.

## Project Structure

```
/ 
├── FirewallDrv/              # Kernel-mode driver
│   ├── common.h              # Shared definitions
│   ├── kutils.h              # Kernel utility classes
│   └── drv.cpp               # Main driver implementation
└── NetBlockProc/             # User-mode management application
    └── Agent.cpp             # Command-line interface
```

## Requirements

- Visual Studio 2019 or later with Windows Driver Kit (WDK)
- Windows 10 or 11 (x64)
- Administrator privileges
- Test signing mode enabled for driver installation

## Building the Project

1. Open the solution in Visual Studio
2. Set the build configuration to `Debug` or `Release` and platform to `x64`
3. Build the solution (F7 or Build → Build Solution)

## Installation

### Enabling Test Signing Mode

Before installing the driver, enable test signing mode:

```
bcdedit /set testsigning on
```

Restart your system for the change to take effect.

### Installing the Driver

1. Open an Administrator command prompt
2. Navigate to the directory containing the built driver
3. Install the driver using the following commands:

```
sc create ProcNetFilter type= kernel binPath= <path-to-driver>\FirewallDrv.sys
sc start ProcNetFilter
```

## Usage

The `Agent` application provides a command-line interface to control the filtering:

```
Agent [Block | Permit | Clear | Isolate | UnIsolate] [ProcessId]
```

### Examples

Block a specific process:
```
Agent Block 1234
```

Allow a previously blocked process:
```
Agent Permit 1234
```

Clear all filtering rules:
```
Agent Clear
```

Isolate the system (block all network traffic):
```
Agent Isolate
```

Restore network connectivity:
```
Agent UnIsolate
```

## How It Works

### WFP Pipeline

1. The kernel driver registers callout functions for specific network layers
2. The user-mode application adds filters that reference these callouts
3. When network traffic matches a filter, WFP invokes the corresponding callout
4. The callout checks if the process ID is in the block list
5. If the process is blocked, the callout returns `FWP_ACTION_BLOCK`, otherwise `FWP_ACTION_PERMIT`

### Process List Management

The driver maintains a thread-safe list of process IDs using:

- A linked list to store process entries
- Spin locks to protect concurrent access
- Custom C++ classes with proper constructors and destructors

### User-Mode and Kernel-Mode Communication

The driver exposes a device interface (`\\.\ProcNetFilter`) that the user-mode application can send I/O control codes (IOCTLs) to:

- `IOCTL_PNF_BLOCK_PROCESS`: Add a process ID to the block list
- `IOCTL_PNF_PERMIT_PROCESS`: Remove a process ID from the block list
- `IOCTL_PNF_CLEAR`: Clear all process IDs from the block list
- `IOCTL_PNF_ISOLATE`: Block all network traffic
- `IOCTL_PNF_UNISOLATE`: Restore normal filtering

## Security Considerations

This is a proof-of-concept and has several limitations:

- No persistence across reboots
- Limited error handling
- No user interface for monitoring or real-time configuration
- No protection against process ID spoofing or tampering

## Uninstallation

To remove the driver:

```
sc stop ProcNetFilter
sc delete ProcNetFilter
```

To disable test signing mode:

```
bcdedit /set testsigning off
```
