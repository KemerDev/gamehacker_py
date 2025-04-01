# GameHacker

GameHacker is a Python module designed for interacting with game memory. It provides tools for reading and modifying memory values, making it useful for debugging, cheating, or automation in game environments.

## Features
- Retrieve current process information
- Initialize FPGA for memory access
- Support for memory mapping and debugging

## Installation
To install GameHacker, use pip:

```sh
pip install gamehacker_py
```

## Usage

```python
from gamehacker import GameHacker

gh = GameHacker()
if gh.init_fpga("process.exe", memMap=True, debug=False, fixcr3=False):
    print("FPGA initialized successfully.")

info = gh.current_process_info

info.base_address
info.base_size
info.PID
info.process_name

result = gh.read(0x14401c990, 4)

print(struct.unpack("I", result))[0] # convert return buffer bytes to uint32 value

# is_heap true bacause the offset we are looking is allocated dynamically
result = gh.find_signature("48 8B 1D ? ? ? ? 48 89 5C 24", info.base_address, info.base_size, True, info.PID)

print(hex(result)) # 0x30d480

# is_heap false because the offset we are looking is static 
result = gh.find_signature("48 8B BF ? ? ? ? 48 8B", info.base_address, info.base_size, False, info.PID)

print(hex(result)) # 0x30d480

# Dump process memory and save it to file
hacker.dump_memory()
```

## API Reference

### `class GameHacker`
Main class for interacting with game memory.

#### Methods:
- `init_fpga(process_name: str, memMap: bool = False, debug: bool = False, fixcr3: bool = False) -> bool`
  - Initializes FPGA for memory access.
  - **Arguments:**
    - `process_name (str)`: Target process name.
    - `memMap (bool)`: Use memory map if `True`.
    - `debug (bool)`: Enable debug output if `True`.
    - `fixcr3 (bool)`: Attempt CR3 fix if `True`.
  - **Returns:** `True` if successful, `False` otherwise.

- `find_signature(self, signature: str, range_start: int, size: int, is_heap: bool, pid: int) -> int:`
  - Scans a memory region for a given signature and returns the found offset or address.
  - **Arguments:**
    - `signature (str)`: The byte pattern to search for, with wildcards represented as '?'. Example: "48 8B 1D ? ? ? ? 48 89 5C 24 ?.
    - `range_start (int)`: The starting address of the memory region to scan.
    - `size (int)`: The side of the memory region to scan.
    - `PID (int, optional)`: The process id to read memory from. If 0, uses the current process.
  - **Returns:** `int` The found offset or address. Returns 0 if the signature is not found.

- More can be found when installed.

## License
This project is licensed under the MIT License.
