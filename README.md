# GameHacker

GameHacker is a Python module designed for interacting with game memory. It provides tools for reading and modifying memory values, making it useful for debugging, cheating, or automation in game environments.

## Features
- Retrieve current process information
- Initialize FPGA for memory access
- Support for memory mapping and debugging

## Installation
To install GameHacker, use pip:

```sh
pip install gamehacker
```

## Usage

```python
from gamehacker import GameHacker

gh = GameHacker()
if gh.init_fpga("game.exe", memMap=True, debug=True):
    print("FPGA initialized successfully.")
```

## API Reference

### `class CurrentProcessInformation`
Represents information about the current process.

#### Attributes:
- `PID (int)`: Process ID
- `base_address (int)`: Base memory address
- `base_size (int)`: Size of the process memory
- `process_name (str)`: Name of the process

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

## License
This project is licensed under the MIT License.
