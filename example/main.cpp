#include "../memory_manager/memory_manager.h"

/*
* this is the example project for memory_manager library by kitodoescode
*/

int main() {
	memory mem;

	if (!mem.attach("notepad.exe")) {
		printf("failed to attach.\n");
		system("pause");
		return 1;
	}

	printf("attached successfully.\n");

	if (!mem.set_backend(backend_t::syscall_indirect)) {
		printf("failed to set backend.\n");
		system("pause");
		return 1;
	}

	printf("set backend to indirect syscalls.\n");

	auto base = mem.get_process_base();
	printf("process base @ 0x%llx\n", base);

	uintptr_t size = 0x100;
	auto allocated = mem.allocate(size, PAGE_READWRITE);
	if (!allocated) {
		printf("failed to allocate memory of size 0x%llx\n", size);
		system("pause");
		return 1;
	}

	printf("allocated memory @ 0x%llx ( size 0x%llx )\n", allocated, size);

	uintptr_t offset = 0x20;
	BYTE example_value = 0x2;
	if (!mem.write<BYTE>(allocated + offset, example_value)) {
		printf("write @ 0x%llx failed.\n", offset);
		system("pause");
		return 1;
	}

	printf("write @ 0x%llx was successful ( written 0x%02x )\n", allocated + offset, example_value);

	auto read_value = mem.read<BYTE>(allocated + offset);
	printf("val @ 0x%llx is 0x%02x\n", allocated + offset, read_value);

	ULONG old_protection;
	ULONG new_protection = PAGE_READONLY;

	if (!mem.protect(allocated, size, new_protection, &old_protection)) {
		printf("failed to change protection of memory @ 0x%llx ( size 0x%llx )\n", allocated, size);
		system("pause");
		return 1;
	}

	printf("changed protection of memory @ 0x%llx ( size 0x%llx ) from %lu to %lu\n", allocated, size, old_protection, new_protection);

	system("pause");
	return 0;
}