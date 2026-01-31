#include "memory.h"

extern "C" {
	dword ntreadidx = 0;
	dword ntwriteidx = 0;
	dword ntallocateidx = 0;
	dword ntprotectidx = 0;

	ptr ntreadsyscall = 0;
	ptr ntwritesyscall = 0;
	ptr ntallocatesyscall = 0;
	ptr ntprotectsyscall = 0;
}

/* main attach function */

bool memory_t::attach_to_process(const str& process_name) {
	printf("[*] [memory_t::attach_to_process] starting. . .\n");

	if (process_name.empty()) {
		printf("[-] [memory_t::attach_to_process] process name is empty.\n");
		return false;
	}

	if (process_name.find(".exe") == str::npos) {
		printf("[!] [memory_t::attach_to_process] process name does not contain \".exe\" extension.\n");
		return false;
	}

	this->process_name = process_name;

	if (strcmp(process_name.data(), "RobloxPlayerBeta.exe") == 0) {
		is_attached_to_roblox = true;
	}

	printf("[*] [memory_t::attach_to_process] attempting to attach to %s. . .\n", process_name.data());

	printf("[*] [memory_t::attach_to_process] attempting to get process id. . .\n");

	if (!get_process_id() || !process_id) {
		printf("[-] [memory_t::attach_to_process] failed to get process id.\n");
		return false;
	}
	else {
		printf("[*] [memory_t::attach_to_process] target process id is %u\n", process_id);
	}

	printf("[*] [memory_t::attach_to_process] attempting to get process handle. . .\n");

	if (!get_process_handle()) {
		printf("[-] [memory_t::attach_to_process] failed to get process handle.\n");
		return false;
	}
	else {
		printf("[*] [memory_t::attach_to_process] target process handle is 0x%p\n", process_handle);
	}

	printf("[*] [memory_t::attach_to_process] attempting to get process base. . .\n");

	if (!get_process_base()) {
		printf("[-] [memory_t::attach_to_process] failed to get process base.\n");
		return false;
	}
	else {
		printf("[*] [memory_t::attach_to_process] target process base is 0x%llx\n", process_base);
	}

	printf("[*] [memory_t::attach_to_process] attempting to initialize syscalls. . .\n");

	if (!initialize_syscalls()) {
		printf("[-] [memory_t::attach_to_process] failed to initialize syscalls.\n");
		return false;
	}
	else {
		printf("[*] [memory_t::attach_to_process] syscalls initialized.\n");
	}

	printf("[+] [memory_t::attach_to_process] attached successfully to %s!\n", process_name.data());

	return true;
}

/* process functions */

bool memory_t::get_process_id() {
	if (process_name.empty()) {
		printf("[-] [memory_t::get_process_id] process name is empty.\n");
		return false;
	}

	PROCESSENTRY32 pe32 = {};
	pe32.dwSize = sizeof(PROCESSENTRY32);

	const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!snapshot || snapshot == INVALID_HANDLE_VALUE) {
		printf("[-] [memory_t::get_process_id] failed to create a snapshot.\n");
		return false;
	}

	if (!Process32First(snapshot, &pe32)) {
		printf("[-] [memory_t::get_process_id] failed to create a snapshot.\n");
		return false;
	}

	do {
		if (strcmp(pe32.szExeFile, process_name.data()) == 0) {
			process_id = pe32.th32ProcessID;
			CloseHandle(snapshot);
			return true;
		}
	} while (Process32Next(snapshot, &pe32));

	CloseHandle(snapshot);
	return false;
}

bool memory_t::get_process_handle() {
	if (process_name.empty()) {
		printf("[-] [memory_t::get_process_handle] process name is empty.\n");
		return false;
	}

	if (!process_id) {
		printf("[-] [memory_t::get_process_base] process id is invalid.\n");
		return false;
	}

	const auto handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, process_id);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		printf("[-] [memory_t::get_process_handle] failed to open process.\n");
		return false;
	}

	process_handle = handle;
	return true;
}

bool memory_t::get_process_base() {
	if (process_name.empty()) {
		printf("[-] [memory_t::get_process_base] process name is empty.\n");
		return false;
	}

	if (!process_id) {
		printf("[-] [memory_t::get_process_base] process id is invalid.\n");
		return false;
	}

	MODULEENTRY32 me32 = {};
	me32.dwSize = sizeof(MODULEENTRY32);

	const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
	if (!snapshot || snapshot == INVALID_HANDLE_VALUE) {
		printf("[-] [memory_t::get_process_base] failed to create a snapshot.\n");
		return false;
	}

	if (Module32First(snapshot, &me32)) {
		process_base = (ptr)(me32.modBaseAddr);
		CloseHandle(snapshot);
		return true;
	}

	CloseHandle(snapshot);
	return false;
}

/* module functions */

hmod memory_t::get_process_module_by_name(const str& module_name) {
	if (module_name.empty()) {
		printf("[-] [memory_t::get_process_module_by_name] module name is empty.\n");
		return 0;
	}

	if (!process_id) {
		printf("[-] [memory_t::get_process_module_by_name] process id is invalid.\n");
		return 0;
	}

	HMODULE modules[1024];
	DWORD needed;

	if (EnumProcessModules(process_handle, modules, sizeof(modules), &needed)) {
		for (unsigned int i = 0; i < (needed / sizeof(HMODULE)); i++) {
			char mod[MAX_PATH];
			if (GetModuleBaseName(process_handle, modules[i], mod, sizeof(mod) / sizeof(char))) {
				if (strcmp(mod, module_name.data()) == 0) {
					return modules[i];
				}
			}
		}
	}

	return 0;
}

ptr memory_t::get_module_base(const hmod& mod) {
	return (ptr)(mod);
}

/* syscall functions */

bool memory_t::initialize_syscalls() {
	auto target_ntdll = get_process_module_by_name("ntdll.dll");
	if (!target_ntdll) {
		printf("[-] [memory_t::initialize_syscalls] failed to find ntdll in target process.\n");
		return false;
	}

	auto local_ntdll = GetModuleHandle("ntdll.dll");
	if (!local_ntdll) {
		printf("[-] [memory_t::initialize_syscalls] failed to load ntdll in our process.\n");
		return false;
	}

	auto local_read = (ptr)(GetProcAddress(local_ntdll, "NtReadVirtualMemory"));
	auto local_write = (ptr)(GetProcAddress(local_ntdll, "NtWriteVirtualMemory"));
	auto local_allocate = (ptr)(GetProcAddress(local_ntdll, "NtAllocateVirtualMemory"));
	auto local_protect = (ptr)(GetProcAddress(local_ntdll, "NtProtectVirtualMemory"));

	if (!local_read || !local_write || !local_allocate || !local_protect) {
		printf("[-] [memory_t::initialize_syscalls] failed to get all syscall funcs in our ntdll.\n");
		return false;
	}

	ntreadidx = get_syscall_idx(local_read);
	ntwriteidx = get_syscall_idx(local_write);
	ntallocateidx = get_syscall_idx(local_allocate);
	ntprotectidx = get_syscall_idx(local_protect);

	auto ntreadfunc = get_target_function_address(local_read, (ptr)(local_ntdll), (ptr)(target_ntdll));
	auto ntwritefunc = get_target_function_address(local_write, (ptr)(local_ntdll), (ptr)(target_ntdll));
	auto ntallocatefunc = get_target_function_address(local_allocate, (ptr)(local_ntdll), (ptr)(target_ntdll));
	auto ntprotectfunc = get_target_function_address(local_protect, (ptr)(local_ntdll), (ptr)(target_ntdll));

	if (!ntreadfunc || !ntwritefunc || !ntallocatefunc || !ntprotectfunc) {
		printf("[-] [memory_t::initialize_syscalls] failed to get all syscall funcs in target ntdll.\n");
		return false;
	}

	ntreadsyscall = ntreadfunc + get_syscall_inst_offset((ptr)(local_ntdll), local_read);
	ntwritesyscall = ntwritefunc + get_syscall_inst_offset((ptr)(local_ntdll), local_write);
	ntallocatesyscall = ntallocatefunc + get_syscall_inst_offset((ptr)(local_ntdll), local_allocate);
	ntprotectsyscall = ntprotectfunc + get_syscall_inst_offset((ptr)(local_ntdll), local_protect);

	return true;
}

dword memory_t::get_syscall_idx(ptr function_address) {
	auto bytes = (BYTE*)(function_address);

	// mov eax, idx | mov = 0xb8
	for (auto i = 0; i < 32; ++i) {
		if (bytes[i] == 0xb8) {
			auto idx = *(dword*)(bytes + i + 1);
			return idx;
		}
	}

	return 0;
}

ptr memory_t::get_function_rva(ptr base, ptr function_address) {
	return function_address - base;
}

ptr memory_t::get_target_function_address(ptr function_address, ptr local_base, ptr target_base) {
	ptr rva = get_function_rva(local_base, function_address);
	return target_base + rva;
}

ptr memory_t::get_syscall_inst_offset(ptr base, ptr function_address) {
	auto bytes = (BYTE*)(function_address);
	auto rva = function_address - base;

	// syscall | syscall = 0xf, 0x5
	for (auto i = 0; i < 0x100; ++i) {
		if (bytes[i] == 0xf && bytes[i + 1] == 0x5) {
			return (ptr)(i);
		}
	}

	return 0;
}

/* roblox functions */

bool roblox_t::get_version() {
	if (!is_attached_to_roblox) {
		printf("[-] [roblox_t::get_version] attached process is not roblox, please try again after attaching to roblox.\n");
		return false;
	}

	std::string version = "version-xxxxxxxxxxxxxxxx";
	char filename[MAX_PATH];

	if (!GetModuleFileNameEx(process_handle, 0, filename, MAX_PATH)) {
		printf("[-] [roblox_t::get_version] failed to get roblox path.\n");
		return false;
	}

	auto path = fs::path(filename);
	version = path.parent_path().filename().string();

	if (version.empty() || strcmp(version.data(), "version-xxxxxxxxxxxxxxxx") == 0) {
		printf("[-] [roblox_t::get_version] failed to get roblox version.\n");
		return false;
	}

	this->version = version;

	return true;
}

str roblox_t::read_string(ptr address) {
	auto len = read<ptr>(address + 0x10);
	if (len > 15) address = read<ptr>(address);
	str str; str.reserve((sz)(len));
	for (sz i = 0; i < (sz)(len); ++i) { auto ch = read<char>(address + i); if (ch == '\0') break; str.push_back(ch); }
	return str;
}

bool roblox_t::write_string(ptr address, const str& new_str) {
	auto str = read<rbx_string>(address);
	if (new_str.length() > str.capacity) {
		while (new_str.length() > str.capacity) {
			str.capacity *= 2;
			str.capacity += 1;
		}
		str.data.pointer = allocate((size_t)(str.capacity));
	}
	str.length = (uintptr_t)(new_str.length());
	if (str.length > 15) {
		if (!write<rbx_string>(address, str)) return false;
		address = str.data.pointer;
	}
	else {
		str.capacity = 15;
		if (!write<rbx_string>(address, str)) return false;
	}
	if (!write_bytes(address, new_str)) return false;
	return true;
}