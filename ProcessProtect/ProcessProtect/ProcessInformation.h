#pragma once
#include <ntddk.h>
#define SystemProcessesAndThreadsInformation 5
#define STATUS_OK 888
#define TARGET_PROCESS_NAME L"PeInternals.exe"


#define PROCESS_TERMINATE 1
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020  


typedef struct _SYSTEM_PROCESSES
{
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    ULONG Reserved[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    KPRIORITY BasePriority;
    ULONG ProcessId;
    ULONG InheritedFromProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    VM_COUNTERS VmCounters;
    IO_COUNTERS IoCounters;
} _SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

NTSTATUS EnumSystemProcess();


NTSYSAPI
NTSTATUS
NTAPI ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
);












