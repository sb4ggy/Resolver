#include "resolver.h"

HANDLE resolver::get_process_id(PCWSTR process_name)
{
	NTSTATUS status;
	ULONG requiredSize = 0;

	status = ZwQuerySystemInformation(5, nullptr, 0, &requiredSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

	if (requiredSize > g_BufferSize) {
		if (g_ProcessInfoBuffer) {
			ExFreePoolWithTag(g_ProcessInfoBuffer, 'enoN');
			g_ProcessInfoBuffer = nullptr;
		}
		g_ProcessInfoBuffer = ExAllocatePoolWithTag(PagedPool, requiredSize, 'enoN');
		g_BufferSize = requiredSize;
	}

	if (!g_ProcessInfoBuffer)
		return nullptr;

	status = ZwQuerySystemInformation(5, g_ProcessInfoBuffer, g_BufferSize, &requiredSize);
	if (!NT_SUCCESS(status))
		return nullptr;

	PSYSTEM_PROCESSES processEntry = (PSYSTEM_PROCESSES)g_ProcessInfoBuffer;
	UNICODE_STRING target;
	RtlInitUnicodeString(&target, process_name);

	do {
		if (processEntry->ProcessName.Length) {
			if (RtlEqualUnicodeString(&processEntry->ProcessName, &target, TRUE)) {
				return (HANDLE)processEntry->ProcessId;
			}
		}
		if (!processEntry->NextEntryDelta) break;
		processEntry = (PSYSTEM_PROCESSES)((BYTE*)processEntry + processEntry->NextEntryDelta);
	} while (true);

	return nullptr;
}

uintptr_t resolver::get_base_address(HANDLE pid)
{
	NTSTATUS status{ };
	PEPROCESS process{ };
	status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status))
		return status;

	PVOID base_address = PsGetProcessSectionBaseAddress(process);

	return (uintptr_t)base_address;
}

BOOLEAN resolver::copy_full_headers(HANDLE pid, uintptr_t base, PIMAGE_NT_HEADERS* out_nth, PUCHAR* out_buffer, PSIZE_T out_size)
{
	if (!out_nth || !out_buffer || !out_size)
		return FALSE;

	*out_nth = nullptr;
	*out_buffer = nullptr;
	*out_size = 0;

	NTSTATUS status;
	PEPROCESS process = nullptr;
	SIZE_T bytes = 0;

	status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status))
		return FALSE;

	IMAGE_DOS_HEADER dos{};
	status = MmCopyVirtualMemory(process, (PVOID)base, PsGetCurrentProcess(), &dos, sizeof(dos), KernelMode, &bytes);

	if (!NT_SUCCESS(status) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
		ObDereferenceObject(process);
		return FALSE;
	}

	ULONG headersSize = 0x1000; 
	MmCopyVirtualMemory(process, (PVOID)(base + dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader.SizeOfHeaders)), PsGetCurrentProcess(), &headersSize, sizeof(headersSize), KernelMode, &bytes);

	if (headersSize < 0x200)
		headersSize = 0x1000;

	UCHAR* buf = (UCHAR*)ExAllocatePoolWithTag(NonPagedPoolNx, headersSize, 'rHeP');
	if (!buf) {
		ObDereferenceObject(process);
		return FALSE;
	}

	status = MmCopyVirtualMemory(process, (PVOID)base, PsGetCurrentProcess(), buf, headersSize, KernelMode, &bytes);

	ObDereferenceObject(process);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(buf, 'rHeP');
		return FALSE;
	}

	PIMAGE_NT_HEADERS nth = RtlImageNtHeader(buf);
	if (!nth) {
		ExFreePoolWithTag(buf, 'rHeP');
		return FALSE;
	}

	*out_nth = nth;
	*out_buffer = buf;
	*out_size = headersSize;

	return TRUE;
}

BOOLEAN resolver::pe_read_rva(HANDLE pid, uintptr_t base,
	const IMAGE_NT_HEADERS* nth,
	ULONG rva, PVOID out, SIZE_T size)
{
	if (!nth || !out || size == 0) return FALSE;

	if (rva >= nth->OptionalHeader.SizeOfImage ||
		size > (SIZE_T)(nth->OptionalHeader.SizeOfImage - rva))
		return FALSE;

	NTSTATUS status;
	PEPROCESS process = nullptr;

	status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status)) return FALSE;

	SIZE_T copied = 0;
	PVOID src = reinterpret_cast<PVOID>(base + rva);

	status = MmCopyVirtualMemory(process, src, PsGetCurrentProcess(), out, size, KernelMode, &copied);

	ObDereferenceObject(process);

	return NT_SUCCESS(status) && copied == size;
}

VOID resolver::print_dos_nt_headers(const IMAGE_DOS_HEADER* dos, const IMAGE_NT_HEADERS* nth)
{
	if (!dos || !nth) return;

	kprintf("=== DOS HEADER ===\n");
	kprintf("  e_magic:   0x%04X ('MZ')  e_lfanew: 0x%08X\n",
		dos->e_magic, dos->e_lfanew);

	kprintf("=== NT HEADERS ===\n");
	kprintf("  Signature: 0x%08X ('PE\\0\\0')\n", nth->Signature);

	const IMAGE_FILE_HEADER& fh = nth->FileHeader;
	kprintf("  FILE_HEADER:\n");
	kprintf("    Machine: 0x%04X  NumberOfSections: %u\n", fh.Machine, fh.NumberOfSections);
	kprintf("    TimeDateStamp: 0x%08X  Characteristics: 0x%04X\n",
		fh.TimeDateStamp, fh.Characteristics);
	kprintf("    NumberOfSymbols: %u  SizeOfOptionalHeader: %u\n",
		fh.NumberOfSymbols, fh.SizeOfOptionalHeader);

	const IMAGE_OPTIONAL_HEADER& oh = nth->OptionalHeader;
	kprintf("  OPTIONAL_HEADER:\n");
	kprintf("    Magic: 0x%04X  Linker: %u.%u\n", oh.Magic, oh.MajorLinkerVersion, oh.MinorLinkerVersion);
	kprintf("    SizeOfCode: 0x%X  SizeOfInitializedData: 0x%X  SizeOfUninitializedData: 0x%X\n",
		oh.SizeOfCode, oh.SizeOfInitializedData, oh.SizeOfUninitializedData);
	kprintf("    AddressOfEntryPoint: 0x%08X  ImageBase: 0x%p\n",
		oh.AddressOfEntryPoint, (PVOID)(ULONG_PTR)oh.ImageBase);
	kprintf("    SectionAlignment: 0x%X  FileAlignment: 0x%X\n",
		oh.SectionAlignment, oh.FileAlignment);
	kprintf("    ImageVersion: %u.%u  Subsystem: 0x%04X\n",
		oh.MajorImageVersion, oh.MinorImageVersion, oh.Subsystem);
	kprintf("    SizeOfImage: 0x%X  SizeOfHeaders: 0x%X  CheckSum: 0x%X\n",
		oh.SizeOfImage, oh.SizeOfHeaders, oh.CheckSum);
	kprintf("    DllCharacteristics: 0x%04X\n", oh.DllCharacteristics);

	kprintf("  DATA_DIRECTORIES (max %u):\n", IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	for (UINT i = 0; i < kmin<UINT>(oh.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); ++i) {
		const IMAGE_DATA_DIRECTORY& d = oh.DataDirectory[i];
		kprintf("    [%02u] RVA: 0x%08X  Size: 0x%08X\n", i, d.VirtualAddress, d.Size);
	}
}

VOID resolver::print_sections(const IMAGE_NT_HEADERS* nth)
{
	if (!nth) return;

	auto* sec = IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS*>(nth));
	kprintf("=== SECTIONS (%lu) ===\n", nth->FileHeader.NumberOfSections);

	for (ULONG i = 0; i < nth->FileHeader.NumberOfSections; ++i) {
		CHAR name[9] = { 0 };
		RtlCopyMemory(name, sec[i].Name, 8);
		kprintf("  [%02lu] %-8s VA:0x%08X VSz:0x%08X RawPtr:0x%08X RawSz:0x%08X Ch:0x%08X\n",
			i, name,
			sec[i].VirtualAddress, sec[i].Misc.VirtualSize,
			sec[i].PointerToRawData, sec[i].SizeOfRawData,
			sec[i].Characteristics);
	}
}

VOID resolver::print_export_dir(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth)
{
	const IMAGE_DATA_DIRECTORY& dd = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	kprintf("=== EXPORT DIRECTORY ===\n");
	if (!dd.VirtualAddress || !dd.Size) {
		kprintf("  <none>\n"); return;
	}

	IMAGE_EXPORT_DIRECTORY exp{};
	if (!pe_read_rva(pid, base, nth, dd.VirtualAddress,
		&exp, kmin<ULONG>(dd.Size, sizeof(exp)))) {
		kprintf("  failed to read export directory\n");
		return;
	}

	kprintf("  Name RVA: 0x%08X  OrdinalBase: %u  Funcs: %u  Names: %u\n",
		exp.Name, exp.Base, exp.NumberOfFunctions, exp.NumberOfNames);

	CHAR nameBuf[256] = { 0 };
	if (exp.Name && pe_read_rva(pid, base, nth, exp.Name, nameBuf, sizeof(nameBuf) - 1)) {
		kprintf("  DLL Name: %s\n", nameBuf);
	}

	ULONG toShow = kmin<ULONG>(exp.NumberOfNames, 32);
	if (exp.AddressOfNames && exp.AddressOfNameOrdinals && exp.AddressOfFunctions && toShow) {
		ULONG* nameRVAs = (ULONG*)ExAllocatePoolWithTag(NonPagedPoolNx, toShow * sizeof(ULONG), 'rPxE');
		USHORT* ords = (USHORT*)ExAllocatePoolWithTag(NonPagedPoolNx, toShow * sizeof(USHORT), 'rOxE');
		ULONG* funcs = (ULONG*)ExAllocatePoolWithTag(NonPagedPoolNx, toShow * sizeof(ULONG), 'rFxE');
		if (nameRVAs && ords && funcs &&
			pe_read_rva(pid, base, nth, exp.AddressOfNames, nameRVAs, toShow * sizeof(ULONG)) &&
			pe_read_rva(pid, base, nth, exp.AddressOfNameOrdinals, ords, toShow * sizeof(USHORT)) &&
			pe_read_rva(pid, base, nth, exp.AddressOfFunctions, funcs, exp.NumberOfFunctions * sizeof(ULONG))) {

			for (ULONG i = 0; i < toShow; ++i) {
				CHAR fn[128] = { 0 };
				pe_read_rva(pid, base, nth, nameRVAs[i], fn, sizeof(fn) - 1);
				ULONG funcRva = funcs[ords[i]];
				kprintf("    %-32s  RVA:0x%08X Ord:%u\n", fn, funcRva, exp.Base + ords[i]);
			}
		}
		else {
			kprintf("  (skipping names: allocation/read failed)\n");
		}
		if (nameRVAs) ExFreePoolWithTag(nameRVAs, 'rPxE');
		if (ords)     ExFreePoolWithTag(ords, 'rOxE');
		if (funcs)    ExFreePoolWithTag(funcs, 'rFxE');
	}
}

VOID resolver::print_import_dir(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth)
{
	const IMAGE_DATA_DIRECTORY& dd = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	kprintf("=== IMPORT DIRECTORY ===\n");
	if (!dd.VirtualAddress || !dd.Size) {
		kprintf("  <none>\n"); return;
	}

	const ULONG maxDesc = 256;
	IMAGE_IMPORT_DESCRIPTOR descs[maxDesc] = {};
	if (!pe_read_rva(pid, base, nth, dd.VirtualAddress, descs, kmin<ULONG>(dd.Size, sizeof(descs)))) {
		kprintf("  failed to read import directory\n"); return;
	}

	for (ULONG idx = 0; idx < maxDesc; ++idx) {
		const IMAGE_IMPORT_DESCRIPTOR& d = descs[idx];
		if (d.OriginalFirstThunk == 0 && d.FirstThunk == 0 && d.Name == 0)
			break;

		CHAR dllName[256] = { 0 };
		if (d.Name) pe_read_rva(pid, base, nth, d.Name, dllName, sizeof(dllName) - 1);
		kprintf("  DLL: %s  OFT:0x%08X  IAT:0x%08X\n", dllName[0] ? dllName : "<unknown>",
			d.OriginalFirstThunk, d.FirstThunk);

		if (d.OriginalFirstThunk) {
#ifdef _WIN64
			ULONGLONG thunks[256] = {};
			pe_read_rva(pid, base, nth, d.OriginalFirstThunk, thunks, sizeof(thunks));
			for (UINT i = 0; i < _countof(thunks) && thunks[i]; ++i) {
				if (thunks[i] & IMAGE_ORDINAL_FLAG64) {
					kprintf("    Ordinal: %llu\n", thunks[i] & 0xFFFF);
				}
				else {
					IMAGE_IMPORT_BY_NAME ibn{};
					if (pe_read_rva(pid, base, nth, (ULONG)thunks[i], &ibn, sizeof(ibn))) {
						CHAR fn[128] = { 0 };
						pe_read_rva(pid, base, nth, (ULONG)thunks[i] + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name),
							fn, sizeof(fn) - 1);
						kprintf("    %s  (Hint:%u)\n", fn, ibn.Hint);
					}
				}
			}
#else
			ULONG thunks[256] = {};
			pe_read_rva(pid, base, nth, d.OriginalFirstThunk, thunks, sizeof(thunks));
			for (UINT i = 0; i < _countof(thunks) && thunks[i]; ++i) {
				if (thunks[i] & IMAGE_ORDINAL_FLAG32) {
					kprintf("    Ordinal: %u\n", thunks[i] & 0xFFFF);
				}
				else {
					IMAGE_IMPORT_BY_NAME ibn{};
					if (pe_read_rva(pid, base, nth, thunks[i], &ibn, sizeof(ibn))) {
						CHAR fn[128] = { 0 };
						pe_read_rva(pid, base, nth, thunks[i] + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name),
							fn, sizeof(fn) - 1);
						kprintf("    %s  (Hint:%u)\n", fn, ibn.Hint);
					}
				}
			}
#endif
		}
	}
}

VOID resolver::print_debug_dir(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth)
{
	const IMAGE_DATA_DIRECTORY& dd = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	kprintf("=== DEBUG DIRECTORY ===\n");
	if (!dd.VirtualAddress || !dd.Size) {
		kprintf("  <none>\n"); return;
	}

	const ULONG maxDbg = 16;
	IMAGE_DEBUG_DIRECTORY dbg[maxDbg] = {};
	ULONG count = kmin<ULONG>(dd.Size / sizeof(IMAGE_DEBUG_DIRECTORY), maxDbg);

	if (!pe_read_rva(pid, base, nth, dd.VirtualAddress, dbg, count * sizeof(IMAGE_DEBUG_DIRECTORY))) {
		kprintf("  failed to read debug directory\n"); return;
	}

	for (ULONG i = 0; i < count; ++i) {
		kprintf("  [#%u] Type:%u Time:0x%08X Size:%u RVA:0x%08X\n",
			i, dbg[i].Type, dbg[i].TimeDateStamp, dbg[i].SizeOfData, dbg[i].AddressOfRawData);

		if (dbg[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW && dbg[i].AddressOfRawData && dbg[i].SizeOfData) {
			UCHAR cv[256] = {};
			if (pe_read_rva(pid, base, nth, dbg[i].AddressOfRawData, cv, kmin<ULONG>(dbg[i].SizeOfData, sizeof(cv)))) {
				if (cv[0] == 'R' && cv[1] == 'S' && cv[2] == 'D' && cv[3] == 'S') {
					const CHAR* path = reinterpret_cast<const CHAR*>(cv + 24); 
					kprintf("    CodeView: %s\n", path);
				}
			}
		}
	}
}


VOID resolver::print_tls_dir(HANDLE pid, uintptr_t base, const IMAGE_NT_HEADERS* nth)
{
	const IMAGE_DATA_DIRECTORY& dd = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	kprintf("=== TLS DIRECTORY ===\n");
	if (!dd.VirtualAddress || !dd.Size) {
		kprintf("  <none>\n"); return;
	}

#ifdef _WIN64
	IMAGE_TLS_DIRECTORY64 tls{};
#else
	IMAGE_TLS_DIRECTORY32 tls{};
#endif
	if (!pe_read_rva(pid, base, nth, dd.VirtualAddress, &tls, kmin<ULONG>(dd.Size, sizeof(tls)))) {
		kprintf("  failed to read TLS directory\n"); return;
	}

#ifdef _WIN64
	kprintf("  StartAddrOfRawData: 0x%llX  EndAddrOfRawData: 0x%llX\n",
		tls.StartAddressOfRawData, tls.EndAddressOfRawData);
	kprintf("  AddressOfIndex: 0x%llX  AddressOfCallBacks: 0x%llX\n",
		tls.AddressOfIndex, tls.AddressOfCallBacks);
#else
	kprintf("  StartAddrOfRawData: 0x%08X  EndAddrOfRawData: 0x%08X\n",
		tls.StartAddressOfRawData, tls.EndAddressOfRawData);
	kprintf("  AddressOfIndex: 0x%08X  AddressOfCallBacks: 0x%08X\n",
		tls.AddressOfIndex, tls.AddressOfCallBacks);
#endif
}

VOID resolver::print_pe_summary(HANDLE pid, uintptr_t base)
{
	PIMAGE_NT_HEADERS nth = nullptr;
	PUCHAR buffer = nullptr;
	SIZE_T size = 0;

	if (!copy_full_headers(pid, base, &nth, &buffer, &size)) {
		kprintf("print_pe_summary: copy_full_headers failed\n");
		return;
	}

	auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		kprintf("print_pe_summary: bad MZ\n");
		ExFreePoolWithTag(buffer, 'rHeP');
		return;
	}

	print_dos_nt_headers(dos, nth);
	print_sections(nth);
	print_export_dir(pid, base, nth);
	print_import_dir(pid, base, nth);
	print_debug_dir(pid, base, nth);
	print_tls_dir(pid, base, nth);

	ExFreePoolWithTag(buffer, 'rHeP'); 
}