/* 
*   ****************************   memory_manager   ****************************
* 
*	a header-only c++ library for windows that simplifies external
*	process memory manipulation.
*	
*	author: kitodoescode
*	version: 1.0.0
*	license: mit
* 
*	copyright (c) 2026 kitodoescode
* 
*   ****************************************************************************
*/

#pragma once

#pragma region includes

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

#pragma endregion

#pragma region type definitions

using read_t = NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using write_t = NTSTATUS(*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using allocate_t = NTSTATUS(*)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG);
using protect_t = NTSTATUS(*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

#pragma endregion

#pragma region enumerations

enum class backend_t {
	winapi,
	ntdll,
	syscall_direct,
	syscall_indirect
};

#pragma endregion

#pragma region structures

struct backend_functions {
	read_t read;
	write_t write;
	allocate_t allocate;
	protect_t protect;
};

#pragma endregion

#pragma region classes

class memory {
public:
	memory();
	~memory();

	bool attach(std::string_view process_name);
	bool set_backend(backend_t backend_type);
	HMODULE get_module(std::string_view module_name);

	/* functions */

	template <typename t>
	t read(uintptr_t address);

	template <typename t>
	std::vector<t> read(uintptr_t address, size_t size);

	template <typename t>
	bool write(uintptr_t address, t value);

	template <typename t>
	bool write(uintptr_t address, const std::vector<t>& bytes);

	bool write(uintptr_t address, std::string_view bytes);

	uintptr_t allocate(size_t size);
	uintptr_t allocate(size_t size, ULONG protection);

	bool protect(uintptr_t address, size_t size, ULONG protection);
	bool protect(uintptr_t address, size_t size, ULONG protection, PULONG old_protection);

	/* getters */

	DWORD     get_process_id()     const { return process_id;     }
	HANDLE    get_process_handle() const { return process_handle; }
	uintptr_t get_process_base()   const { return process_base;   }
private:
	backend_functions _backend;

	std::string process_name = "";
	DWORD process_id = 0;
	HANDLE process_handle = nullptr;
	uintptr_t process_base = 0;

	bool initialize();
};

#pragma endregion

#pragma region helpers

namespace detail {
	namespace backends {
		inline bool initialized = false;
		inline backend_functions winapi{};
		inline backend_functions ntdll{};
		inline backend_functions syscall_direct{};
		inline backend_functions syscall_indirect{};
	}

	namespace stubs {
		inline std::vector<uintptr_t> allocated_stubs{};

		inline static const BYTE direct[] = {
				0x49, 0x89, 0xCA,             // mov r10, rcx
				0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0x0 (index placeholder)
				0x0F, 0x05,                   // syscall
				0xC3                          // ret
		};

		inline static const BYTE indirect[] = {
				0x49, 0x89, 0xca,                              // mov r10, rcx
				0xb8, 0x00, 0x00, 0x00, 0x00,                  // mov eax, 0x0 (index placeholder)
				0xff, 0x25, 0x00, 0x00, 0x00, 0x00,            // jmp qword ptr [rip+0]
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 0x0 (syscall instruction address placeholder)
		};

		inline void* create_direct_syscall_stub(DWORD syscall_index) {
			auto allocated = VirtualAlloc(nullptr, sizeof(direct), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!allocated) return nullptr;
			BYTE stub[sizeof(direct)];
			memcpy(stub, direct, sizeof(direct));
			memcpy(stub + 4, &syscall_index, sizeof(DWORD));
			memcpy(allocated, stub, sizeof(direct));
			allocated_stubs.push_back((uintptr_t)(allocated));
			return allocated;
		}

		inline void* create_indirect_syscall_stub(DWORD syscall_index, uintptr_t syscall_inst_addr) {
			auto allocated = VirtualAlloc(nullptr, sizeof(indirect), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!allocated) return nullptr;
			BYTE stub[sizeof(indirect)];
			memcpy(stub, indirect, sizeof(indirect));
			memcpy(stub + 4, &syscall_index, sizeof(DWORD));
			memcpy(stub + 14, &syscall_inst_addr, sizeof(uintptr_t));
			memcpy(allocated, stub, sizeof(indirect));
			allocated_stubs.push_back((uintptr_t)(allocated));
			return allocated;
		}
	}

	inline DWORD get_syscall_index(uintptr_t func_addr) {
		auto bytes = (BYTE*)(func_addr);

		/* mov eax, idx
		*  mov = 0xb8 */

		for (auto i = 0; i < 32; i++) {
			if (bytes[i] == 0xb8) {
				auto idx = *(DWORD*)(bytes + i + 1);
				return idx;
			}
		}

		return 0;
	}

	inline uintptr_t get_syscall_instruction_offset(uintptr_t func_addr) {
		auto bytes = (BYTE*)(func_addr);

		/* syscall = 0xf, 0x5 */
		for (auto i = 0; i < 0x100; ++i) {
			if (bytes[i] == 0xf && bytes[i + 1] == 0x5) {
				return (uintptr_t)(i);
			}
		}

		return 0;
	}

	inline DWORD get_process_id(std::string_view process_name) {
		PROCESSENTRY32 pe32 = {};
		pe32.dwSize = sizeof(PROCESSENTRY32);

		const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!snapshot || snapshot == INVALID_HANDLE_VALUE) return 0;

		if (!Process32First(snapshot, &pe32)) return 0;

		do {
			if (process_name == pe32.szExeFile) {
				CloseHandle(snapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(snapshot, &pe32));

		CloseHandle(snapshot);
		return 0;
	}

	inline HANDLE get_process_handle(DWORD process_id) {
		if (!process_id) return 0;

		/*
		* we remove process terminate since its mostly unused 
		* and incase process all access gets silently flagged
		*/

		auto handle = OpenProcess(PROCESS_ALL_ACCESS & ~PROCESS_TERMINATE, 0, process_id);

		if (handle == INVALID_HANDLE_VALUE) return 0;
		return handle;
	}

	inline uintptr_t get_process_base(DWORD process_id) {
		if (!process_id) return 0;

		MODULEENTRY32 me32 = {};
		me32.dwSize = sizeof(MODULEENTRY32);

		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
		if (!snapshot || snapshot == INVALID_HANDLE_VALUE) return 0;

		if (Module32First(snapshot, &me32)) {
			CloseHandle(snapshot);
			return (uintptr_t)(me32.modBaseAddr);
		}

		CloseHandle(snapshot);
		return 0;
	}
}

#pragma endregion

#pragma region memory definitions

inline memory::memory() {
	if (!initialize()) throw std::runtime_error("Failed to initialize memory manager.");
	_backend = detail::backends::winapi;
}

inline memory::~memory() {
	if (process_handle) {
		CloseHandle(process_handle);
		process_handle = nullptr;
	}

	for (auto stub : detail::stubs::allocated_stubs)
		if (stub)
			VirtualFree((LPVOID)stub, 0, MEM_RELEASE);

	detail::stubs::allocated_stubs.clear();
}

inline bool memory::initialize() {
	if (detail::backends::initialized) return true;

	/* winapi backend */

	detail::backends::winapi.read = [](HANDLE h, void* remote_addr, void* local_buffer, SIZE_T size, SIZE_T* bytes_read) -> NTSTATUS {
		auto res = ReadProcessMemory(h, (LPCVOID)remote_addr, local_buffer, size, bytes_read);
		return res ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		};

	detail::backends::winapi.write = [](HANDLE h, void* remote_addr, void* local_buffer, SIZE_T size, SIZE_T* bytes_written) -> NTSTATUS {
		auto res = WriteProcessMemory(h, remote_addr, local_buffer, size, bytes_written);
		return res ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		};

	detail::backends::winapi.allocate = [](HANDLE h, void** base, ULONG, SIZE_T* size, ULONG alloc_type, ULONG protect) -> NTSTATUS {
		*base = VirtualAllocEx(h, nullptr, *size, alloc_type, protect);
		return *base ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		};

	detail::backends::winapi.protect = [](HANDLE h, void** base, SIZE_T* size, ULONG new_protect, PULONG old_protect) -> NTSTATUS {
		auto res = VirtualProtectEx(h, *base, *size, new_protect, old_protect);
		return res ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		};

	/* ntdll backend */

	auto ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll || ntdll == INVALID_HANDLE_VALUE) return false;

	auto ntread = GetProcAddress(ntdll, "NtReadVirtualMemory");
	if (!ntread) return false;
	detail::backends::ntdll.read = (read_t)(ntread);

	auto ntwrite = GetProcAddress(ntdll, "NtWriteVirtualMemory");
	if (!ntwrite) return false;
	detail::backends::ntdll.write = (write_t)(ntwrite);

	auto ntallocate = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	if (!ntallocate) return false;
	detail::backends::ntdll.allocate = (allocate_t)(ntallocate);

	auto ntprotect = GetProcAddress(ntdll, "NtProtectVirtualMemory");
	if (!ntprotect) return false;
	detail::backends::ntdll.protect = (protect_t)(ntprotect);

	/* common syscall stuff */

	auto read_idx = detail::get_syscall_index((uintptr_t)(ntread));
	auto write_idx = detail::get_syscall_index((uintptr_t)(ntwrite));
	auto allocate_idx = detail::get_syscall_index((uintptr_t)(ntallocate));
	auto protect_idx = detail::get_syscall_index((uintptr_t)(ntprotect));

	if (!read_idx || !write_idx || !allocate_idx || !protect_idx) return false;

	/* direct syscall backend */

	auto read_stub_direct = detail::stubs::create_direct_syscall_stub(read_idx);
	if (!read_stub_direct) return false;
	detail::backends::syscall_direct.read = (read_t)(read_stub_direct);

	auto write_stub_direct = detail::stubs::create_direct_syscall_stub(write_idx);
	if (!write_stub_direct) return false;
	detail::backends::syscall_direct.write = (write_t)(write_stub_direct);

	auto allocate_stub_direct = detail::stubs::create_direct_syscall_stub(allocate_idx);
	if (!allocate_stub_direct) return false;
	detail::backends::syscall_direct.allocate = (allocate_t)(allocate_stub_direct);

	auto protect_stub_direct = detail::stubs::create_direct_syscall_stub(protect_idx);
	if (!protect_stub_direct) return false;
	detail::backends::syscall_direct.protect = (protect_t)(protect_stub_direct);

	/* indirect syscall initialization */

	auto read_syscall_inst = (uintptr_t)(ntread) + detail::get_syscall_instruction_offset((uintptr_t)(ntread));
	auto write_syscall_inst = (uintptr_t)(ntwrite) + detail::get_syscall_instruction_offset((uintptr_t)(ntwrite));
	auto allocate_syscall_inst = (uintptr_t)(ntallocate) + detail::get_syscall_instruction_offset((uintptr_t)(ntallocate));
	auto protect_syscall_inst = (uintptr_t)(ntprotect) + detail::get_syscall_instruction_offset((uintptr_t)(ntprotect));

	auto read_stub_indirect = detail::stubs::create_indirect_syscall_stub(read_idx, read_syscall_inst);
	if (!read_stub_indirect) return false;
	detail::backends::syscall_indirect.read = (read_t)(read_stub_indirect);

	auto write_stub_indirect = detail::stubs::create_indirect_syscall_stub(write_idx, write_syscall_inst);
	if (!write_stub_indirect) return false;
	detail::backends::syscall_indirect.write = (write_t)(write_stub_indirect);

	auto allocate_stub_indirect = detail::stubs::create_indirect_syscall_stub(allocate_idx, allocate_syscall_inst);
	if (!allocate_stub_indirect) return false;
	detail::backends::syscall_indirect.allocate = (allocate_t)(allocate_stub_indirect);

	auto protect_stub_indirect = detail::stubs::create_indirect_syscall_stub(protect_idx, protect_syscall_inst);
	if (!protect_stub_indirect) return false;
	detail::backends::syscall_indirect.protect = (protect_t)(protect_stub_indirect);

	detail::backends::initialized = true;

	return true;
}

inline bool memory::attach(std::string_view process_name) {
	if (process_name.empty()) return false;

	if (process_handle) {
		CloseHandle(process_handle);
		process_handle = nullptr;
	}

	this->process_name = process_name;

	auto pid = detail::get_process_id(process_name);
	if (!pid) return false;
	this->process_id = pid;

	auto handle = detail::get_process_handle(pid);
	if (!handle || handle == INVALID_HANDLE_VALUE) return false;
	this->process_handle = handle;

	auto base = detail::get_process_base(pid);
	if (!base) return false;
	this->process_base = base;

	return true;
}

inline bool memory::set_backend(backend_t backend) {
	switch (backend) {
	case backend_t::winapi:
		_backend = detail::backends::winapi;
		break;
	case backend_t::ntdll:
		_backend = detail::backends::ntdll;
		break;
	case backend_t::syscall_direct:
		_backend = detail::backends::syscall_direct;
		break;
	case backend_t::syscall_indirect:
		_backend = detail::backends::syscall_indirect;
		break;
	default:
		return false;
	}
	return true;
}

inline HMODULE memory::get_module(std::string_view module_name) {
	if (module_name.empty()) return 0;
	if (!process_id || !process_handle || process_handle == INVALID_HANDLE_VALUE) return 0;

	HMODULE modules[1024];
	DWORD needed;

	if (K32EnumProcessModules(process_handle, modules, sizeof(modules), &needed)) {
		for (UINT i = 0; i < (needed / sizeof(HMODULE)); i++) {
			char mod[MAX_PATH];
			if (K32GetModuleBaseNameA(process_handle, modules[i], mod, sizeof(mod) / sizeof(char))) 
				if (module_name == mod)
					return modules[i];
		}
	}

	return 0;
}

template <typename t>
inline t memory::read(uintptr_t address) {
	t buffer{};
	SIZE_T bytes_read;
	auto result = _backend.read(process_handle, (void*)(address), (void*)(&buffer), sizeof(t), &bytes_read);
	return (NT_ERROR(result) || bytes_read != sizeof(t)) ? t() : buffer;
}

template <typename t>
inline std::vector<t> memory::read(uintptr_t address, size_t size) {
	std::vector<t> buffer(size);
	SIZE_T bytes_read;
	auto result = _backend.read(process_handle, (void*)(address), (void*)(buffer.data()), size, &bytes_read);
	return (NT_ERROR(result) || bytes_read != size) ? t() : buffer;
}

template <typename t>
inline bool memory::write(uintptr_t address, t value) {
	SIZE_T bytes_written;
	auto result = _backend.write(process_handle, (void*)(address), (void*)(&value), sizeof(t), &bytes_written);
	return (NT_ERROR(result) || bytes_written != sizeof(t)) ? false : true;
}

template <typename t>
inline bool memory::write(uintptr_t address, const std::vector<t>& bytes) {
	SIZE_T bytes_written;
	auto result = _backend.write(process_handle, (void*)(address), (void*)(bytes.data()), bytes.size(), &bytes_written);
	return (NT_ERROR(result) || bytes_written != bytes.size()) ? false : true;
}

inline bool memory::write(uintptr_t address, std::string_view bytes) {
	SIZE_T bytes_written;
	auto result = _backend.write(process_handle, (void*)(address), (void*)(bytes.data()), bytes.size(), &bytes_written);
	return (NT_ERROR(result) || bytes_written != bytes.size()) ? false : true;
}

inline uintptr_t memory::allocate(size_t size) {
	void* allocated = nullptr;
	SIZE_T region_size = size;
	auto result = _backend.allocate(process_handle, &allocated, 0, &region_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	return NT_ERROR(result) ? 0 : (uintptr_t)(allocated);
}

inline uintptr_t memory::allocate(size_t size, ULONG protection) {
	void* allocated = nullptr;
	SIZE_T region_size = size;
	auto result = _backend.allocate(process_handle, &allocated, 0, &region_size, MEM_RESERVE | MEM_COMMIT, protection);
	return NT_ERROR(result) ? 0 : (uintptr_t)(allocated);
}

inline bool memory::protect(uintptr_t address, size_t size, ULONG protection) {
	auto base = (void*)(address);
	ULONG old;
	auto result = _backend.protect(process_handle, &base, &size, protection, &old);
	return (NT_ERROR(result)) ? false : true;
}

inline bool memory::protect(uintptr_t address, size_t size, ULONG protection, PULONG old_protection) {
	auto base = (void*)(address);
	auto result = _backend.protect(process_handle, &base, &size, protection, old_protection);
	return (NT_ERROR(result)) ? false : true;
}

#pragma endregion