#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <unordered_map>
#include <cstdint>
#include <tlhelp32.h>
#include <psapi.h>
#include <ntstatus.h>
#include <winternl.h>
#include <filesystem>

// memory manager, version 0.2
// a single-file, memory management library made specifically for windows cheat tools wanting to manipulate memory with ease
// this library uses indirect syscalls for all its functions such as read, write, allocate, etc.
// includes a roblox version of the memory manager for some roblox-specific extras such as get_version(), read_string() etc.
// also includes a syscall stub parser to get syscall indexes and addresses in runtime instead of static values

extern "C" {
	// stuff for indirect syscalls
	extern DWORD ntread_idx;
	extern DWORD ntwrite_idx;
	extern DWORD ntalloc_idx;
	extern DWORD ntprot_idx;

	extern uintptr_t ntread_syscall_inst_addr;
	extern uintptr_t ntwrite_syscall_inst_addr;
	extern uintptr_t ntalloc_syscall_inst_addr;
	extern uintptr_t ntprot_syscall_inst_addr;

	// direct
	NTSTATUS ntread(HANDLE, void*, void*, SIZE_T, SIZE_T*);
	NTSTATUS ntwrite(HANDLE, void*, void*, SIZE_T, SIZE_T*);
	NTSTATUS ntalloc(HANDLE, void**, ULONG, SIZE_T*, ULONG, ULONG);
	NTSTATUS ntprot(HANDLE, void**, SIZE_T*, ULONG, PULONG);

	// indirect
	NTSTATUS ntread_i(HANDLE, void*, void*, SIZE_T, SIZE_T*);
	NTSTATUS ntwrite_i(HANDLE, void*, void*, SIZE_T, SIZE_T*);
	NTSTATUS ntalloc_i(HANDLE, void**, ULONG, SIZE_T*, ULONG, ULONG);
	NTSTATUS ntprot_i(HANDLE, void**, SIZE_T*, ULONG, PULONG);
}

enum memory_type {
	win_api,
	nt_win_api,
	direct_syscall,
	indirect_syscall
};

struct memory_functions {
	NTSTATUS (*read)(HANDLE, void*, void*, SIZE_T, SIZE_T*);
	NTSTATUS (*write)(HANDLE, void*, void*, SIZE_T, SIZE_T*);
	NTSTATUS (*allocate)(HANDLE, void**, ULONG, SIZE_T*, ULONG, ULONG);
	NTSTATUS (*protect)(HANDLE, void**, SIZE_T*, ULONG, PULONG);
};

struct nt_funcs {
	NTSTATUS (*read)(HANDLE, void*, void*, SIZE_T, SIZE_T*);
	NTSTATUS (*write)(HANDLE, void*, void*, SIZE_T, SIZE_T*);
	NTSTATUS (*allocate)(HANDLE, void**, ULONG, SIZE_T*, ULONG, ULONG);
	NTSTATUS (*protect)(HANDLE, void**, SIZE_T*, ULONG, PULONG);

	bool load() {
		HMODULE ntdll = GetModuleHandle("ntdll.dll");
		if (!ntdll) return false;
		read = (decltype(read))(GetProcAddress(ntdll, "NtReadVirtualMemory"));
		write = (decltype(write))(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
		allocate = (decltype(allocate))(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
		protect = (decltype(protect))(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
	}
};

/* default memory manager class */

class memory_t {
public:
	std::string process_name;
	DWORD process_id;
	HANDLE process_handle;
	uintptr_t process_base;
	memory_type type;
	memory_functions funcs;
	bool is_attached_to_roblox;
	bool is_initialized;

	memory_t();
	void initialize_functions();
	void set_memory_type(memory_type& type);

	bool attach_to_process(const std::string& process_name);

	bool initialize_syscalls();

	bool get_process_id();
	bool get_process_handle();
	bool get_process_base();

	HMODULE get_process_module_by_name(const std::string& module_name);
	uintptr_t get_module_base(const HMODULE& mod); // a basic helper

	template <typename t>
	t read(uintptr_t address) {
		t buf{};
		SIZE_T bytes_read;
		auto res = funcs.read(process_handle, (void*)(address), (void*)(&buf), sizeof(t), &bytes_read);
		if (NT_ERROR(res) || bytes_read != sizeof(t)) {
			//printf("[-] read failed at 0x%llx ( status - 0x%lx )\n", address, res);
			return t();
		}
		return buf;
	}

	template <typename t>
	bool write(uintptr_t address, t value) {
		SIZE_T bytes_written;
		auto res = funcs.write(process_handle, (void*)(address), (void*)(&value), sizeof(t), &bytes_written);
		if (NT_ERROR(res) || bytes_written != sizeof(t)) {
			//printf("[-] write failed @ 0x%llx ( status - 0x%lx )\n", address, res);
			return false;
		}
		return true;
	}

	template <typename t>
	std::vector<t> read_bytes(uintptr_t address, size_t size) {
		std::vector<t> buf{};
		SIZE_T bytes_read;
		auto res = funcs.read(process_handle, (void*)(address), (void*)(&buf), size, &bytes_read);
		if (NT_ERROR(res) || bytes_read != size) {
			//printf("[-] read_bytes failed at 0x%llx ( status - 0x%lx )\n", address, res);
			return t();
		}
		return buf;
	}

	template <typename t>
	bool write_bytes(uintptr_t address, const std::vector<t>& bytes) {
		SIZE_T bytes_written;
		auto res = funcs.write(process_handle, (void*)(address), (void*)(bytes.data()), bytes.size(), &bytes_written);
		if (NT_ERROR(res) || bytes_written != bytes.size()) {
			//printf("[-] write_bytes failed @ 0x%llx ( status - 0x%lx )\n", address, res);
			return false;
		}
		return true;
	}

	// overload for writing string bytes
	bool write_bytes(uintptr_t address, const std::string& bytes) {
		SIZE_T bytes_written;
		auto res = funcs.write(process_handle, (void*)(address), (void*)(bytes.data()), bytes.size(), &bytes_written);
		if (NT_ERROR(res) || bytes_written != bytes.size()) {
			//printf("[-] write_bytes failed @ 0x%llx ( status - 0x%lx )\n", address, res);
			return false;
		}
		return true;
	}

	uintptr_t allocate(size_t size) {
		void* allocated = nullptr;
		auto res = funcs.allocate(process_handle, &allocated, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (NT_ERROR(res)) {
			//printf("[-] allocation failed ( err code 0x%lx )\n", res);
			return 0;
		}
		return (uintptr_t)(allocated);
	}

	bool protect(uintptr_t address, size_t size, ULONG protection) {
		auto base = (void*)(address);
		ULONG old;
		auto res = funcs.protect(process_handle, &base, &size, protection, &old);
		if (NT_ERROR(res)) {
			//printf("[-] protection change failed at 0x%llx\n", address);
			return false;
		}
		return true;
	}

	// special overload, incase old protection is needed to be retrieved
	bool protect(uintptr_t address, size_t size, ULONG protection, PULONG old_protection) {
		auto base = (void*)(address);
		auto res = funcs.protect(process_handle, &base, &size, protection, old_protection);
		if (NT_ERROR(res)) {
			//printf("[-] protection change failed at 0x%llx\n", address);
			return false;
		}
		return true;
	}
private:
	bool syscalls_ready = false;
	DWORD get_syscall_idx(uintptr_t function_address);                             // to be used on local ntdll
	uintptr_t get_function_rva(uintptr_t base, uintptr_t function_address);        // to be used on local ntdll
	uintptr_t get_target_function_address(uintptr_t function_address, uintptr_t local_base, uintptr_t target_base);
	uintptr_t get_syscall_inst_offset(uintptr_t base, uintptr_t function_address); // to be used on local ntdll
}; // class memory_t

/* roblox memory manager class */

struct rbx_string {
	union {
		uint8_t raw[16];
		uintptr_t pointer;
	} data;

	uintptr_t length;
	uintptr_t capacity;
};

class roblox_t : public memory_t {
public:
	std::string version;

	bool get_version();

	std::string read_string(uintptr_t address);

	bool write_string(uintptr_t address, const std::string& new_string);
}; // class roblox_t