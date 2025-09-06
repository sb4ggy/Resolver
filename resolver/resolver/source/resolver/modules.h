#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <cstdint>
#include <ntimage.h>
#include <wdf.h>
#include <stdlib.h>
#include <stdarg.h>

typedef unsigned int UINT;

EXTERN_C PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
EXTERN_C NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID BaseOfImage);
EXTERN_C NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
EXTERN_C NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);


typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           State;
	LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
	ULONG            NextEntryDelta;
	ULONG            ThreadCount;
	ULONG            Reserved1[6];
	LARGE_INTEGER    CreateTime;
	LARGE_INTEGER    UserTime;
	LARGE_INTEGER    KernelTime;
	UNICODE_STRING   ProcessName;
	KPRIORITY        BasePriority;
	SIZE_T           ProcessId;
	SIZE_T           InheritedFromProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS      VmCounters;
	IO_COUNTERS      IoCounters;
	SYSTEM_THREADS   Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;