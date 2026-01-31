# memory_manager
```cpp
// memory manager
// a single-file, memory management library made specifically for windows cheat tools wanting to manipulate memory with ease
// this library uses indirect syscalls for all its functions such as read, write, allocate, etc.
// includes a roblox version of the memory manager for some roblox-specific extras such as get_version(), read_string() etc.
// also includes a syscall stub parser to get syscall indexes and addresses in runtime instead of static values
```
# code example
```cpp
#include "memory.h" // library file
#include "offsets.h"

int main() {
  // sry for messy example :sob:

  // main classes: memory_t, roblox_t
  // roblox_t is derived from memory_t to add special functions specifically for roblox

	printf("hi\n");

	auto roblox = new roblox_t();

	roblox->attach_to_process("RobloxPlayerBeta.exe"); // process name

	printf("roblox base 0x%llx\n", roblox->process_base);

	roblox->get_version(); // roblox_t specific
	
	printf("roblox version %s\n", roblox->version.c_str());

  // using the "ptr" type defined in library
	auto fakedm = roblox->read<ptr>(roblox->process_base + Offsets::FakeDataModel::Pointer);
	auto dm = roblox->read<ptr>(fakedm + Offsets::FakeDataModel::RealDataModel);

	printf("fakedatamodel 0x%llx\n", fakedm);
	printf("datamodel 0x%llx\n", dm);

	system("pause");
	return 0;
}
```
