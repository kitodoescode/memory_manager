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

// memory manager, version 0.1
// a single-file, memory management library made specifically for windows cheat tools wanting to manipulate memory with ease
// this library uses indirect syscalls for all its functions such as read, write, allocate, etc.
// includes a roblox version of the memory manager for some roblox-specific extras such as get_version(), read_string() etc.
// also includes a syscall stub parser to get syscall indexes and addresses in runtime instead of static values

// todo:
// - make memory manager use direct syscall as fallback incase target application does not have ntdll loaded
// - give user choice to between windows api, nt windows api, direct syscall and indirect syscall

/* custom types & defines */

using str = std::string;
using ptr = uintptr_t;
using sz = size_t;
using hmod = HMODULE;
using dword = DWORD;
using handle = HANDLE;
using ul = ULONG;
using pul = PULONG;

template <typename t>
using vec = std::vector<t>;

namespace fs = std::filesystem;

/* default memory manager class */

extern "C" {
	extern dword ntreadidx;
	extern dword ntwriteidx;
	extern dword ntallocateidx;
	extern dword ntprotectidx;

	extern ptr ntreadsyscall;
	extern ptr ntwritesyscall;
	extern ptr ntallocatesyscall;
	extern ptr ntprotectsyscall;

	NTSTATUS ntreadvirtualmemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
	NTSTATUS ntwritevirtualmemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
	NTSTATUS ntallocatevirtualmemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
	NTSTATUS ntprotectvirtualmemory(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
}

class memory_t {
public:
	str process_name;
	dword process_id;
	handle process_handle;
	ptr process_base;

	bool is_attached_to_roblox;

	memory_t() : process_name(""), process_id(0), process_handle(nullptr), process_base(0), is_attached_to_roblox(false) {}

	bool attach_to_process(const str& process_name);

	bool initialize_syscalls();

	bool get_process_id();
	bool get_process_handle();
	bool get_process_base();
	
	hmod get_process_module_by_name(const str& module_name);
	ptr get_module_base(const hmod& mod); // a basic helper

	template <typename t>
	t read(ptr address) {
		t buf{};
		sz bytes_read;
		auto res = ntreadvirtualmemory(process_handle, (void*)(address), (void*)(&buf), sizeof(t), &bytes_read);
		if (NT_ERROR(res) || bytes_read != sizeof(t)) {
			printf("[-] read failed at 0x%llx ( status - 0x%lx )\n", address, res);
			return t();
		}
		return buf;
	}

	template <typename t>
	bool write(ptr address, t value) {
		sz bytes_written;
		auto res = ntwritevirtualmemory(process_handle, (void*)(address), (void*)(&value), sizeof(t), &bytes_written);
		if (NT_ERROR(res) || bytes_written != sizeof(t)) {
			printf("[-] write failed @ 0x%llx ( status - 0x%lx )\n", address, res);
			return false;
		}
		return true;
	}

	template <typename t>
	vec<t> read_bytes(ptr address, sz size) {
		vec<t> buf{};
		sz bytes_read;
		auto res = ntreadvirtualmemory(process_handle, (void*)(address), (void*)(&buf), size, &bytes_read);
		if (NT_ERROR(res) || bytes_read != size) {
			printf("[-] read_bytes failed at 0x%llx ( status - 0x%lx )\n", address, res);
			return t();
		}
		return buf;
	}

	template <typename t>
	bool write_bytes(ptr address, const vec<t> bytes) {
		sz bytes_written;
		auto res = ntwritevirtualmemory(process_handle, (void*)(address), (void*)(bytes.data()), bytes.size(), &bytes_written);
		if (NT_ERROR(res) || bytes_written != bytes.size()) {
			printf("[-] write_bytes failed @ 0x%llx ( status - 0x%lx )\n", address, res);
			return false;
		}
		return true;
	}

	// overload for writing string bytes
	bool write_bytes(ptr address, const str bytes) {
		sz bytes_written;
		auto res = ntwritevirtualmemory(process_handle, (void*)(address), (void*)(bytes.data()), bytes.size(), &bytes_written);
		if (NT_ERROR(res) || bytes_written != bytes.size()) {
			printf("[-] write_bytes failed @ 0x%llx ( status - 0x%lx )\n", address, res);
			return false;
		}
		return true;
	}

	ptr allocate(sz size) {
		void* allocated = nullptr;
		auto res = ntallocatevirtualmemory(process_handle, &allocated, 0, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (NT_ERROR(res)) {
			printf("[-] allocation failed ( err code 0x%lx )\n", res);
			return 0;
		}
		return (uintptr_t)(allocated);
	}

	bool protect(ptr address, sz size, ul protection) {
		auto base = (void*)(address);
		ul old;
		auto res = ntprotectvirtualmemory(process_handle, &base, &size, protection, &old);
		if (NT_ERROR(res)) {
			printf("[-] protection change failed at 0x%llx\n", address);
			return false;
		}
		return true;
	}

	// special overload, incase old protection is needed to be retrieved
	bool protect(ptr address, sz size, ul protection, pul old_protection) {
		auto base = (void*)(address);
		auto res = ntprotectvirtualmemory(process_handle, &base, &size, protection, old_protection);
		if (NT_ERROR(res)) {
			printf("[-] protection change failed at 0x%llx\n", address);
			return false;
		}
		return true;
	}
private:
	bool syscalls_ready = false;

	dword get_syscall_idx(ptr function_address);                 // to be used on local ntdll
	ptr get_function_rva(ptr base, ptr function_address);        // to be used on local ntdll
	ptr get_target_function_address(ptr function_address, ptr local_base, ptr target_base);
	ptr get_syscall_inst_offset(ptr base, ptr function_address); // to be used on local ntdll
}; // class memory_t

/* roblox memory manager class */

struct rbx_string {
	union {
		uint8_t raw[16];
		ptr pointer;
	} data;

	ptr length;
	ptr capacity;
};

class roblox_t : public memory_t {
public:
	str version;

	bool get_version();

	str read_string(ptr address);

	bool write_string(ptr address, const str& new_string);
}; // class roblox_t