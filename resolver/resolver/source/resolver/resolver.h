#include "modules.h"

namespace resolver
{
	inline PVOID g_ProcessInfoBuffer = nullptr;
	inline ULONG g_BufferSize = 0;

	HANDLE get_process_id(PCWSTR process_name);
	uintptr_t get_base_address(HANDLE pid);

    BOOLEAN copy_full_headers(HANDLE pid, uintptr_t base, PIMAGE_NT_HEADERS* out_nth, PUCHAR* out_buffer, PSIZE_T out_size);

    BOOLEAN pe_read_rva(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth, ULONG rva, PVOID out, SIZE_T size);

    VOID print_pe_summary(HANDLE pid, uintptr_t base);

    VOID print_dos_nt_headers(const IMAGE_DOS_HEADER* dos, const IMAGE_NT_HEADERS* nth);
    VOID print_sections(const IMAGE_NT_HEADERS* nth);
    VOID print_export_dir(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth);
    VOID print_import_dir(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth);
    VOID print_debug_dir(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth);
    VOID print_tls_dir(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth);

    template<typename T>
    static inline T kmin(T a, T b) { return (a < b) ? a : b; }
}

static inline VOID kprintf(PCSTR fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    vDbgPrintEx(0, 0, fmt, ap);
    va_end(ap);
}

