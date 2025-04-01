"""
Type stubs for the gamehacker module.
"""
from typing import List, Tuple, Union


class CurrentProcessInformation:
    """
    Represents information about the current process.
    """
    PID: int
    base_address: int
    base_size: int
    process_name: str

class GameHacker:
    """
    Main class for interacting with game memory.
    """

    current_process_info: CurrentProcessInformation

    def __init__(self) -> None:
        """
        Initializes the GameHacker object.
        """
        ...

    def init_fpga(self, process_name: str, memMap: bool = False, debug: bool = False, cache_pml4: bool = False) -> bool:
        """
        Initialize FPGA for memory access.
        
        Args:
            process_name: Target process name
            memMap: Use memory map if True
            debug: Enable debug output if True
            fixcr3: Attempt CR3 fix if True
            
        Returns:
            bool: True if successful, False otherwise
        """
        ...

    def close(self) -> None:
        """Clean up resources, close handles, and free loaded libraries."""
        ...

    def get_pid_from_name(self, process_name: str) -> int:
        """
        Get PID from process name.
        
        Args:
            process_name: Name of target process
            
        Returns:
            int: Process ID or 0 if not found
        """
        ...

    def get_pid_list_from_name(self, name: str) -> List[int]:
        """
        Get list of PIDs matching process name.
        
        Args:
            name: Process name (can be partial)
            
        Returns:
            List[int]: List of matching PIDs
        """
        ...

    def get_module_list(self, process_name: str) -> List[str]:
        """
        Get list of modules loaded by a process.
        
        Args:
            process_name: Target process name
            
        Returns:
            List[str]: List of module names
        """
        ...

    def get_export_table_address(self, import_name: str, process_name: str, module_name: str) -> int:
        """
        Get address of an exported function.
        
        Args:
            import_name: Name of exported function
            process_name: Process containing the module
            module_name: Module containing the export
            
        Returns:
            int: Virtual address of export or 0 if not found
        """
        ...

    def get_import_table_address(self, import_name: str, process_name: str, module_name: str) -> int:
        """
        Get address of an imported function.
        
        Args:
            import_name: Name of imported function
            process_name: Process containing the module
            module_name: Module containing the import
            
        Returns:
            int: Virtual address of import or 0 if not found
        """
        ...

    def fix_cr3(self, cache_pml4: bool = False) -> bool:
        """
        Attempt to fix CR3 for the current process.
        
        Returns:
            bool: True if successful, False otherwise
        """
        ...

    def virt_to_phys(self, virtual_address: int) -> Tuple[bool, int]:
        """
        Convert virtual address to physical address.
        
        Args:
            va: Virtual address to convert
            
        Returns:
            Tuple[bool, int]: (success, physical_address)
        """
        ...
    def dump_memory(self, address: int, path: str) -> None:
        """
        Dump process memory to file.
        
        Args:
            address: Starting address to dump
            path: Output file path
            
        Returns:
            bool: True if successful, False otherwise
        """
        ...

    def find_signature(self, signature: str, range_start: int, size: int, is_heap: bool, pid: int) -> int:
        """
        Scans a memory region for a given signature and returns the found offset or address.

        Args:
            signature (str): The byte pattern to search for, with wildcards represented as '?'.
                            Example: "48 8B 1D ? ? ? ? 48 89 5C 24 ?"
            range_start (int): The starting address of the memory region to scan.
            size (int): The size of the memory region to scan.
            heap_function (bool, optional): If True, calculates a relative offset for heap functions.
                                           If False, returns the raw found offset. Defaults to False.
            PID (int, optional): The Process ID to read memory from. If 0, uses the current process. Defaults to 0.

        Returns:
            int: The found offset or address. Returns 0 if the signature is not found.

        Note:
            - The function internally caches the memory dump for subsequent calls.
            - Wildcards in the signature are ignored during comparison.
        """
        ...

    def read(self, address: int, size: int) -> bytes:
        """
        Read from process memory.
        
        Args:
            address: Source address
            buffer: Buffer to store data
            size: Size to read
            pid: Source process ID (0 = current)
            
        Returns:
            bool: True if successful, False otherwise
        """
        ...

    def read_with_pid(self, address: int, size: int, pid: int) -> bytes:
        """
        Read from process memory.
        
        Args:
            address: Source address
            buffer: Buffer to store data
            size: Size to read
            pid: Source process ID (0 = current)
            
        Returns:
            bool: True if successful, False otherwise
        """
        ...

    def write(self, address: int, buffer: bytes, format: str) -> bool:
        """
        Write to process memory.
        
        Args:
            address: Target address
            buffer: Data to write
            size: Size of data
            pid: Target process ID (0 = current)
            
        Returns:
            bool: True if successful, False otherwise
        """
        ...
    
    def write_with_pid(self, address: int, buffer: bytes, format: str, pid: int) -> bool:
        """
        Write to process memory.
        
        Args:
            address: Target address
            buffer: Data to write
            size: Size of data
            pid: Target process ID (0 = current)
            
        Returns:
            bool: True if successful, False otherwise
        """
        ...

    def ReadString(self, address: int, length: int) -> str:
        """
        Read string from process memory.
        
        Args:
            address: Source address
            length: Maximum length to read
            
        Returns:
            str: Read string or empty string on failure
        """
        ...

    def create_scatter_handle(self) -> int:
        """
        Create scatter handle for batch operations.
        
        Args:
            pid: Target process ID (0 = current)
            
        Returns:
            int: Handle or 0 on failure
        """
        ...

    def create_scatter_handle_with_pid(self, pid: int) -> int:
        """
        Create scatter handle for batch operations.
        
        Args:
            pid: Target process ID (0 = current)
            
        Returns:
            int: Handle or 0 on failure
        """
        ...

    def close_scatter_handle(self, handle: int) -> None:
        """
        Close a scatter handle.
        
        Args:
            handle: Handle to close
        """
        ...

    def add_scatter_read_request(self, handle: int, address: int, size: int) -> bytes:
        """
        Adds a scatter read request.

        Args:
            handle (int): The scatter handle.
            address (int): The memory address to read from.
            size (int): The number of bytes to read.

        Returns:
            buffer (bytes): The read memory buffer with the specified size.
                can be converted to whatever variable using struct.unpack().
        """
        ...

    def add_scatter_write_request(self, handle: int, address: int, buffer: bytes, format: str) -> None:
        """
        Adds a scatter write request.

        Args:
            handle (int): The scatter handle.
            address (int): The memory address to write to.
            buffer (bytes): The data to write.
            format (str, optional): The struct format string for serialization. Defaults to "".
                (See `write` for details on format strings.)
        """
        ...

    def execute_scatter_read(self, handle: int) -> None:
        """
        Execute scatter read operations.
        
        Args:
            handle: Scatter handle
            pid: Target process ID (0 = current)
        """
        ...

    def execute_scatter_write(self, handle: int) -> None:
        """
        Execute scatter write operations.
        
        Args:
            handle: Scatter handle
            pid: Target process ID (0 = current)
        """
        ...

__version__: str = "1.0.0"