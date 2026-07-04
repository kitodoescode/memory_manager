# memory_manager

A header-only C++ library for Windows that simplifies external process memory manipulation.  
It supports multiple memory backends - winapi, ntdll exports, direct syscalls, and indirect syscalls.

---

## Features

* Header-only
* Simple and clean API
* Runtime backend switching
* Typed memory reading and writing
* Bulk reads into typed `std::vector` containers
* Allocation and protection changing
* Module lookup

---

## Backends

| Backend            | Description                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `winapi`           | Uses the standard Windows API functions (`ReadProcessMemory` etc.).                                                |
| `ntdll`            | Uses the NT functions exported by `ntdll.dll`.                                                                     |
| `syscall_direct`   | Executes direct system calls through allocated syscall stubs.                                                      |
| `syscall_indirect` | Executes indirect system calls through allocated syscall stubs that jump into `ntdll.dll`.                         |

Backends can be changed at runtime using the `set_backend` function like such:

```cpp
mem.set_backend(backend_t::winapi);
mem.set_backend(backend_t::ntdll);
mem.set_backend(backend_t::syscall_direct);
mem.set_backend(backend_t::syscall_indirect);
```

---

## Project Layout

```text
memory_manager/
│
├── example/
│   ├── main.cpp
│   └── example.vcxproj
│
├── memory_manager/
│   ├── memory_manager.h
│   └── memory_manager.vcxproj
│
├── LICENSE
├── README.md
└── memory_manager.sln
```

---

## How To Use

Simply copy `memory_manager/memory_manager.h` into your project and include it.

```cpp
#include "memory_manager.h"
```

No additional steps are required.

---

## Public API (Exposed Functions)

### Process

```cpp
bool attach(std::string_view process_name);

bool set_backend(backend_t backend);

HMODULE get_module(std::string_view module_name);

DWORD get_process_id() const;
HANDLE get_process_handle() const;
uintptr_t get_process_base() const;
```

### Memory

```cpp
template<typename T>
T read(uintptr_t address);

template<typename T>
std::vector<T> read(uintptr_t address, size_t count);

template<typename T>
bool write(uintptr_t address, T value);

template<typename T>
bool write(uintptr_t address, const std::vector<T>& values);

bool write(uintptr_t address, std::string_view bytes);

uintptr_t allocate(size_t size);

uintptr_t allocate(size_t size, ULONG protection);

bool protect(uintptr_t address, size_t size, ULONG protection);

bool protect(uintptr_t address, size_t size, ULONG protection, PULONG old_protection);
```

---

## Example

```cpp
#include "memory_manager.h"

int main()
{
    memory mem;

    if (!mem.attach("notepad.exe"))
        return 1;

    mem.set_backend(backend_t::syscall_indirect);

    auto base = mem.get_process_base();

    printf("process base address : 0x%p\n", (void*)base);
}
```

A complete example project showcasing the library is included in the `example/` directory.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for more information.
