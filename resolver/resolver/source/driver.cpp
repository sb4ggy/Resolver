#include "resolver/resolver.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pDriverObject);
    UNREFERENCED_PARAMETER(pRegistryPath);

    HANDLE pid = resolver::get_process_id(L"test_program.exe");
    if (!pid) { kprintf("pid not found\n"); return STATUS_NOT_FOUND; }

    uintptr_t base = resolver::get_base_address(pid);
    if (!base) { kprintf("base not found\n"); return STATUS_NOT_FOUND; }

    resolver::print_pe_summary(pid, base);

    return STATUS_SUCCESS;
}
