#include "pch.h"
#include "GameHacker.h"
#include <iostream>
#include <thread>
#include <Python.h>

std::string GetPydPath() {
    PyObject* sys_module = PyImport_ImportModule("sys");
    if (!sys_module) {
        LOG("[!] Failed to import sys module\n");
        return "";
    }

    PyObject* modules_dict = PyObject_GetAttrString(sys_module, "modules");
    Py_DECREF(sys_module);
    if (!modules_dict) {
        LOG("[!] Failed to get sys.modules\n");
        return "";
    }

    PyObject* gamehacker_module = PyDict_GetItemString(modules_dict, "gamehacker");
    Py_DECREF(modules_dict);
    if (!gamehacker_module) {
        LOG("[!] Failed to find gamehacker module in sys.modules\n");
        return "";
    }

    PyObject* file_attr = PyObject_GetAttrString(gamehacker_module, "__file__");
    if (!file_attr) {
        LOG("[!] Failed to get __file__ attribute of gamehacker module\n");
        return "";
    }

    const char* file_path = PyUnicode_AsUTF8(file_attr);
    Py_DECREF(file_attr);

    if (!file_path) {
        LOG("[!] Failed to convert __file__ to string\n");
        return "";
    }

    return std::string(file_path);
}

GameHacker::GameHacker() {
    std::filesystem::path libs_path;

    // Get the path of the .pyd file
    std::string pyd_path = GetPydPath();
    if (!pyd_path.empty()) {
        libs_path = std::filesystem::path(pyd_path).parent_path();
        LOG("[...] Using DLL path from .pyd location: %s\n", libs_path.string().c_str());
    } else {
        LOG("[!] Failed to determine .pyd location, falling back to default paths\n");
    }

    // Try loading DLLs from the determined path
    modules.VMM = LoadLibraryA((libs_path / "vmm.dll").string().c_str());
    modules.FTD3XX = LoadLibraryA((libs_path / "FTD3XX.dll").string().c_str());
    modules.LEECHCORE = LoadLibraryA((libs_path / "leechcore.dll").string().c_str());

    // If still not found, try Windows system directories
    if (!modules.VMM) modules.VMM = LoadLibraryA("vmm.dll");
    if (!modules.FTD3XX) modules.FTD3XX = LoadLibraryA("FTD3XX.dll");
    if (!modules.LEECHCORE) modules.LEECHCORE = LoadLibraryA("leechcore.dll");

    if (!modules.VMM || !modules.FTD3XX || !modules.LEECHCORE) {
        LOG("Failed to load libraries from: %s\n", libs_path.string().c_str());
        LOG("vmm.dll: %p\n", modules.VMM);
        LOG("FTD3XX.dll: %p\n", modules.FTD3XX);
        LOG("leechcore.dll: %p\n", modules.LEECHCORE);
        THROW("[!] Could not load required libraries\n");
    }

    LOG("[+] Libraries loaded successfully from: %s\n", libs_path.string().c_str());
}

GameHacker::~GameHacker()
{
    if (this->current_process.vHandle) {
        VMMDLL_Close(this->current_process.vHandle);
    }
    
    // Free loaded libraries
    if (modules.VMM) FreeLibrary(modules.VMM);
    if (modules.FTD3XX) FreeLibrary(modules.FTD3XX);
    if (modules.LEECHCORE) FreeLibrary(modules.LEECHCORE);
    
    DMA_INITIALIZED = false;
    PROCESS_INITIALIZED = false;

	delete[] this->dump;
}

void GameHacker::Close()
{
    if (this->current_process.vHandle) {
        VMMDLL_Close(this->current_process.vHandle);
    }
    
    // Free loaded libraries
    if (modules.VMM) FreeLibrary(modules.VMM);
    if (modules.FTD3XX) FreeLibrary(modules.FTD3XX);
    if (modules.LEECHCORE) FreeLibrary(modules.LEECHCORE);
    
    DMA_INITIALIZED = false;
    PROCESS_INITIALIZED = false;

	delete[] this->dump;
}

bool GameHacker::DumpMemoryMap(LPCSTR args[], int argc)
{
    VMM_HANDLE handle = VMMDLL_Initialize(argc, args);

    if (!handle)
    {
        LOG("[!] Failed to open VMM handle\n");
        return false;
    }

    PVMMDLL_MAP_PHYSMEM pPhysMemMap = NULL;

    if (!VMMDLL_Map_GetPhysMem(handle, &pPhysMemMap))
    {
        LOG("[!] Failed to get physical memory map\n");
        VMMDLL_Close(handle);
        return false;
    }

    if (pPhysMemMap->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION)
    {
        LOG("[!] invalid VMM map version\n");
        VMMDLL_MemFree(pPhysMemMap);
        VMMDLL_Close(handle);
        return false;
    }

    if (pPhysMemMap->cMap == 0)
	{
		printf("[!] Failed to get physical memory map\n");
		VMMDLL_MemFree(pPhysMemMap);
		VMMDLL_Close(handle);
		return false;
	}

    std::stringstream sb;

    for (DWORD i = 0; i < pPhysMemMap->cMap; i++)
    {
        sb << std::hex << pPhysMemMap->pMap[i].pa << " " << (pPhysMemMap->pMap[i].pa + pPhysMemMap->pMap[i].cb - 1) << std::endl;
    }

    auto temp_path = std::filesystem::current_path();
    std::ofstream nFile(temp_path / "mmap.txt");
    nFile << sb.str();
    nFile.close();

    VMMDLL_MemFree(pPhysMemMap);
    LOG("Successfully dumped memory map to file!\n");

    Sleep(3000);
    VMMDLL_Close(handle);

    return true;
}

unsigned char abort2[4] = {0x10, 0x00, 0x10, 0x00};

bool GameHacker::SetFPGA()
{
    ULONG64 qwID = 0, qwVersionMajor = 0, qwVersionMinor = 0;

	VMMDLL_ConfigGet(this->current_process.vHandle, LC_OPT_FPGA_FPGA_ID, &qwID);
	VMMDLL_ConfigGet(this->current_process.vHandle, LC_OPT_FPGA_VERSION_MAJOR, &qwVersionMajor);
	VMMDLL_ConfigGet(this->current_process.vHandle, LC_OPT_FPGA_VERSION_MINOR, &qwVersionMinor);

    LOG("[+] VMMDLL_ConfigGet");
	LOG(" ID = %lli", qwID);
	LOG(" VERSION = %lli.%lli\n", qwVersionMajor, qwVersionMinor);

    if ((qwVersionMajor >= 4) && ((qwVersionMajor >= 5) || (qwVersionMinor >= 7)))
	{
		HANDLE handle;
		LC_CONFIG config = { .dwVersion = LC_CONFIG_VERSION, .szDevice = "existing"};
		handle = LcCreate(&config);
		if (!handle)
		{
			LOG("[!] Failed to create FPGA device\n");
			return false;
		}

		LcCommand(handle, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x002, 4, reinterpret_cast<PBYTE>(&abort2), NULL, NULL);
		LOG("[-] Register auto cleared\n");
		LcClose(handle);
	}

	return true;
}

bool GameHacker::InitFPGA(std::string process_name, bool memMap, bool debug, bool fixcr3)
{

    if (!DMA_INITIALIZED)
    {
        LOG("[...] VMM inizializing...\n");
    reinit:
        LPCSTR args[] = {const_cast<LPCSTR>(""), const_cast<LPCSTR>("-device"), const_cast<LPCSTR>("fpga://algo=0"), const_cast<LPCSTR>(""), const_cast<LPCSTR>(""), const_cast<LPCSTR>(""), const_cast<LPCSTR>("")};
        DWORD argc = 3;
    
        if (debug)
        {
            args[argc++] = const_cast<LPCSTR>("-v");
            args[argc++] = const_cast<LPCSTR>("-printf");
        }

        if (memMap)
        {
			LOG("[+] Creating mmap.txt\n");
            auto temp_path = std::filesystem::current_path();
            auto path = temp_path / "mmap.txt";
            bool dumped = false;

			LOG("%s\n", path.string().c_str());

            if (!std::filesystem::exists(path))
            {
                dumped = this->DumpMemoryMap(args, argc);
            }
            else
            {
                dumped = true;
            }

            LOG("dumping memory map to file...\n");

			if (!dumped)
			{
				LOG("[!] ERROR: Could not dump memory map!\n");
				LOG("Defaulting to no memory map!\n");
			}
			else
			{
				LOG("Dumped memory map!\n");
				args[argc++] = const_cast<LPSTR>("-memmap");
				args[argc++] = const_cast<LPSTR>(path.string().c_str());
			}
        }

        this->current_process.vHandle = VMMDLL_Initialize(argc, args);

        if (!this->current_process.vHandle)
        {
            if (memMap)
            {
                memMap = false;
                goto reinit;
            }

            LOG("[!] Initialization failed! Is the DMA in use or disconnected?\n");
			return false;
        }

        ULONG64 FPGA_ID = 0, DEVICE_ID = 0;

        VMMDLL_ConfigGet(this->current_process.vHandle, LC_OPT_FPGA_FPGA_ID, &FPGA_ID);
        VMMDLL_ConfigGet(this->current_process.vHandle, LC_OPT_FPGA_DEVICE_ID, &DEVICE_ID);

        LOG("FPGA ID: %llu\n", FPGA_ID);
		LOG("DEVICE ID: %llu\n", DEVICE_ID);
		LOG("success!\n");
        
        if (!this->SetFPGA())
        {
            LOG("[!] Could not set FPGA\n");
            VMMDLL_Close(this->current_process.vHandle);
            return false;
        }

        DMA_INITIALIZED = TRUE;
    }
    else
    {
        LOG("DMA already initialized\n");
    }

    if (PROCESS_INITIALIZED)
    {
        LOG("Process already initialized\n");
        return true;
    }

    this->current_process.PID = this->GetPidFromName(process_name);
	if (!this->current_process.PID)
	{
		LOG("[!] Could not get PID from name!\n");
		return false;
	}

	this->GetProcessInfo();

	this->current_process.process_name = process_name;

	if (fixcr3)
	{
		if (!this->FixCr3())
			std::cout << "Failed to fix CR3" << std::endl;
		else
			std::cout << "CR3 fixed" << std::endl;
	}

	LOG("[...] Getting process information...\n");

	LOG("Process information of %s\n", process_name.c_str());
	LOG("PID: %i\n", this->current_process.PID);
	LOG("Base Address: 0x%p\n", this->current_process.base_address);
	LOG("Base Size: 0x%p\n", this->current_process.base_size);

	PROCESS_INITIALIZED = TRUE;

	return true;
}

DWORD GameHacker::GetPidFromName(std::string process_name)
{
	DWORD pid = 0;
	VMMDLL_PidGetFromName(this->current_process.vHandle, (LPSTR)process_name.c_str(), &pid);
	return pid;
}

std::vector<int> GameHacker::GetPidListFromName(std::string name)
{
	PVMMDLL_PROCESS_INFORMATION process_info = NULL;
	DWORD total_processes = 0;
	std::vector<int> list = { };

	if (!VMMDLL_ProcessGetInformationAll(this->current_process.vHandle, &process_info, &total_processes))
	{
		LOG("[!] Failed to get process list\n");
		return list;
	}

	for (size_t i = 0; i < total_processes; i++)
	{
		auto process = process_info[i];
		if (strstr(process.szNameLong, name.c_str()))
			list.push_back(process.dwPID);
	}

	return list;
}

std::vector<std::string> GameHacker::GetModuleList(std::string process_name)
{
	std::vector<std::string> list = { };
	PVMMDLL_MAP_MODULE module_info;
	if (!VMMDLL_Map_GetModuleU(this->current_process.vHandle, this->current_process.PID, &module_info, VMMDLL_MODULE_FLAG_NORMAL))
	{
		LOG("[!] Failed to get module list\n");
		return list;
	}

	for (size_t i = 0; i < module_info->cMap; i++)
	{
		auto module = module_info->pMap[i];
		list.push_back(module.uszText);
	}

	return list;
}

void GameHacker::GetProcessInfo()
{
	PVMMDLL_MAP_MODULEENTRY module_entry;
	bool result = VMMDLL_Map_GetModuleFromNameU(this->current_process.vHandle, this->current_process.PID, this->current_process.process_name.c_str(), &module_entry, 0);
	
	if (!result)
	{
		printf("[!] Failed to get process information\n");
        VMMDLL_MemFree(module_entry); 
		module_entry = NULL;
		return;
	}

	this->current_process.base_address = module_entry->vaBase;
	this->current_process.base_size = module_entry->cbImageSize;

	VMMDLL_MemFree(module_entry);
	module_entry = NULL;
}

uintptr_t GameHacker::GetExportTableAddress(std::string import, std::string process, std::string module)
{
	PVMMDLL_MAP_EAT eat_map = NULL;
	PVMMDLL_MAP_EATENTRY export_entry;
	bool result = VMMDLL_Map_GetEATU(this->current_process.vHandle, this->GetPidFromName(process) /*| VMMDLL_PID_PROCESS_WITH_KERNELMEMORY*/, (LPSTR)module.c_str(), &eat_map);
	if (!result)
	{
		LOG("[!] Failed to get Export Table\n");
		return 0;
	}

	if (eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION)
	{
		VMMDLL_MemFree(eat_map);
		eat_map = NULL;
		LOG("[!] Invalid VMM Map Version\n");
		return 0;
	}

	uintptr_t addr = 0;
	for (int i = 0; i < eat_map->cMap; i++)
	{
		export_entry = eat_map->pMap + i;
		if (strcmp(export_entry->uszFunction, import.c_str()) == 0)
		{
			addr = export_entry->vaFunction;
			break;
		}
	}

	VMMDLL_MemFree(eat_map);
	eat_map = NULL;

	return addr;
}

uintptr_t GameHacker::GetImportTableAddress(std::string import, std::string process, std::string module)
{
	PVMMDLL_MAP_IAT iat_map = NULL;
	PVMMDLL_MAP_IATENTRY import_entry;
	bool result = VMMDLL_Map_GetIATU(this->current_process.vHandle, this->GetPidFromName(process) /*| VMMDLL_PID_PROCESS_WITH_KERNELMEMORY*/, (LPSTR)module.c_str(), &iat_map);
	if (!result)
	{
		LOG("[!] Failed to get Import Table\n");
		return 0;
	}

	if (iat_map->dwVersion != VMMDLL_MAP_IAT_VERSION)
	{
		VMMDLL_MemFree(iat_map);
		iat_map = NULL;
		LOG("[!] Invalid VMM Map Version\n");
		return 0;
	}

	uintptr_t addr = 0;
	for (int i = 0; i < iat_map->cMap; i++)
	{
		import_entry = iat_map->pMap + i;
		if (strcmp(import_entry->uszFunction, import.c_str()) == 0)
		{
			addr = import_entry->vaFunction;
			break;
		}
	}

	VMMDLL_MemFree(iat_map);
	iat_map = NULL;

	return addr;
}

uint64_t cbSize = 0x80000;

// Callback for VfsFileListU
VOID cbAddFile(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
	if (strcmp(uszName, "dtb.txt") == 0)
		cbSize = cb;
}

struct Info
{
	uint32_t index;
	uint32_t process_id;
	uint64_t dtb;
	uint64_t kernelAddr;
	std::string name;
};

bool GameHacker::FixCr3()
{
	PVMMDLL_MAP_MODULEENTRY module_entry;
	bool result = VMMDLL_Map_GetModuleFromNameU(this->current_process.vHandle, this->current_process.PID, (LPSTR)this->current_process.process_name.c_str(), &module_entry, NULL);
	if (result)
	{
		//return true; //PREVENTS USING CACHED PML4
	}

	if (!VMMDLL_InitializePlugins(this->current_process.vHandle))
	{
		LOG("[-] Failed VMMDLL_InitializePlugins call\n");
		return false;
	}

	//have to sleep a little or we try reading the file before the plugin initializes fully
	std::this_thread::sleep_for(std::chrono::milliseconds(500));

	while (true)
	{
		BYTE bytes[4] = { 0 };
		DWORD i = 0;
		auto nt = VMMDLL_VfsReadW(this->current_process.vHandle, (LPWSTR)L"\\misc\\procinfo\\progress_percent.txt", bytes, 3, &i, 0);
		if (nt == VMMDLL_STATUS_SUCCESS && atoi((LPSTR)bytes) == 100)
			break;

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	VMMDLL_VFS_FILELIST2 VfsFileList;
	VfsFileList.dwVersion = VMMDLL_VFS_FILELIST_VERSION;
	VfsFileList.h = 0;
	VfsFileList.pfnAddDirectory = 0;
	VfsFileList.pfnAddFile = cbAddFile; //dumb af callback who made this system

	result = VMMDLL_VfsListU(this->current_process.vHandle, (LPSTR)"\\misc\\procinfo\\", &VfsFileList);
	if (!result)
		return false;

	//read the data from the txt and parse it
	const size_t buffer_size = cbSize;
	std::unique_ptr<BYTE[]> bytes(new BYTE[buffer_size]);
	DWORD j = 0;
	auto nt = VMMDLL_VfsReadW(this->current_process.vHandle, (LPWSTR)L"\\misc\\procinfo\\dtb.txt", bytes.get(), buffer_size - 1, &j, 0);
	if (nt != VMMDLL_STATUS_SUCCESS)
		return false;

	std::vector<uint64_t> possible_dtbs;
	std::string lines(reinterpret_cast<char*>(bytes.get()));
	std::istringstream iss(lines);
	std::string line;

	while (std::getline(iss, line))
	{
		Info info = { };

		std::istringstream info_ss(line);
		if (info_ss >> std::hex >> info.index >> std::dec >> info.process_id >> std::hex >> info.dtb >> info.kernelAddr >> info.name)
		{
			if (info.process_id == 0) //parts that lack a name or have a NULL pid are suspects
				possible_dtbs.push_back(info.dtb);
			if (this->current_process.process_name.find(info.name) != std::string::npos)
				possible_dtbs.push_back(info.dtb);
		}
	}

	//loop over possible dtbs and set the config to use it til we find the correct one
	for (size_t i = 0; i < possible_dtbs.size(); i++)
	{
		auto dtb = possible_dtbs[i];
		VMMDLL_ConfigSet(this->current_process.vHandle, VMMDLL_OPT_PROCESS_DTB | this->current_process.PID, dtb);
		result = VMMDLL_Map_GetModuleFromNameU(this->current_process.vHandle, this->current_process.PID, (LPSTR)this->current_process.process_name.c_str(), &module_entry, NULL);
		if (result)
		{
			LOG("[+] Patched DTB\n");
			static ULONG64 pml4_first[512];
			static ULONG64 pml4_second[512];
			DWORD readsize;

			LOG("[+] Reading PML4 table from DTB: 0x%llx\n", dtb);

			if (!VMMDLL_MemReadEx(this->current_process.vHandle, -1, dtb, reinterpret_cast<PBYTE>(pml4_first), sizeof(pml4_first), (PDWORD)&readsize,
				VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
				LOG("[!] Failed to read PML4 the first time\n");
				return false;
			}
			LOG("[+] First PML4 read successful, size: %d\n", readsize);

			if (!VMMDLL_MemReadEx(this->current_process.vHandle, -1, dtb, reinterpret_cast<PBYTE>(pml4_second), sizeof(pml4_second), (PDWORD)&readsize,
				VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
				LOG("[!] Failed to read PML4 the second time\n");
				return false;
			}
			LOG("[+] Second PML4 read successful, size: %d\n", readsize);

			if (memcmp(pml4_first, pml4_second, sizeof(pml4_first)) != 0) {
				LOG("[!] PML4 mismatch between reads\n");
				return false;
			}
			LOG("[+] PML4 verification successful, tables match\n");

			LOG("[+] Setting up PML4 cache\n");
			VMMDLL_MemReadEx((VMM_HANDLE)-666, 333, (ULONG64)pml4_first, 0, 0, 0, 0);

			LOG("[+] Configuring process DTB\n");
			VMMDLL_ConfigSet(this->current_process.vHandle, VMMDLL_OPT_PROCESS_DTB | current_process.PID, 666);

			LOG("[+] Cache initialization complete\n");
			return true;
		}
	}

	LOG("[-] Failed to patch module\n");
	return false;
}

bool GameHacker::VirtToPhys(uint64_t va, uint64_t& pa)
{
	if (VMMDLL_MemVirt2Phys(this->current_process.vHandle, this->current_process.PID, va, &pa)) {
		return true;
	}
	return false;
}

bool GameHacker::DumpMemory(uintptr_t address, std::string path)
{
	LOG("[!] Memory dumping currently does not rebuild the IAT table, imports will be missing from the dump.\n");
	IMAGE_DOS_HEADER dos;
	Read(address, &dos, sizeof(IMAGE_DOS_HEADER));

	//Check if memory has a PE 
	if (dos.e_magic != 0x5A4D) //Check if it starts with MZ
	{
		LOG("[-] Invalid PE Header\n");
		return false;
	}

	IMAGE_NT_HEADERS64 nt;
	Read(address + dos.e_lfanew, &nt, sizeof(IMAGE_NT_HEADERS64));

	//Sanity check
	if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		LOG("[-] Failed signature check\n");
		return false;
	}
	//Shouldn't change ever. so const 
	const size_t target_size = nt.OptionalHeader.SizeOfImage;
	//Crashes if we don't make it a ptr :(
	auto target = std::unique_ptr<uint8_t[]>(new uint8_t[target_size]);

	//Read whole modules memory
	Read(address, target.get(), target_size);
	auto nt_header = (PIMAGE_NT_HEADERS64)(target.get() + dos.e_lfanew);
	auto sections = (PIMAGE_SECTION_HEADER)(target.get() + dos.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader);

	for (size_t i = 0; i < nt.FileHeader.NumberOfSections; i++, sections++)
	{
		//Rewrite the file offsets to the virtual addresses
		LOG("[!] Rewriting file offsets at 0x%p size 0x%p\n", sections->VirtualAddress, sections->Misc.VirtualSize);
		sections->PointerToRawData = sections->VirtualAddress;
		sections->SizeOfRawData = sections->Misc.VirtualSize;
	}

	//Rebuild import table

	//LOG("[!] Creating new import section\n");

	//Create New Import Section

	//Build new import Table

	//Dump file
	const auto dumped_file = CreateFileW(std::wstring(path.begin(), path.end()).c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_COMPRESSED, NULL);
	if (dumped_file == INVALID_HANDLE_VALUE)
	{
		LOG("[!] Failed creating file: %i\n", GetLastError());
		return false;
	}

	if (!WriteFile(dumped_file, target.get(), static_cast<DWORD>(target_size), NULL, NULL))
	{
		LOG("[!] Failed writing file: %i\n", GetLastError());
		CloseHandle(dumped_file);
		return false;
	}
}

void Parse(char* combo, char* pattern, char* mask)
{
    char lastChar = ' ';
    unsigned int j = 0;

    for (unsigned int i = 0; i < strlen(combo); i++)
    {
        if ((combo[i] == '?' || combo[i] == '*') && (lastChar != '?' && lastChar != '*'))
        {
            pattern[j] = mask[j] = '?';
            j++;
        }

        else if (isspace(lastChar))
        {
            pattern[j] = lastChar = (char)strtol(&combo[i], 0, 16);
            mask[j] = 'x';
            j++;
        }
        lastChar = combo[i];
    }
    pattern[j] = mask[j] = '\0';
}

char* ScanBasic(char* pattern, char* mask, char* begin, intptr_t size)
{
    intptr_t patternLen = strlen(mask);

    for (int i = 0; i < size; i++)
    {
        bool found = true;
        for (int j = 0; j < patternLen; j++)
        {
            if (mask[j] != '?' && pattern[j] != *(char*)((intptr_t)begin + i + j))
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return (begin + i);
        }
    }
    return nullptr;
}

char* Scan(char* signature, char* begin, size_t size)
{
	char pattern[1000];
	char mask[1000];
	Parse(signature, pattern, mask);
	return ScanBasic(pattern, mask, begin, size);
}

int FindFirstWildcardByteIndex(const char* signature) {
    if (!signature) return -1;

    std::string sigStr(signature);
    std::istringstream iss(sigStr);
    std::vector<std::string> bytes;
    std::string byte;

    // Split by spaces
    while (iss >> byte) {
        bytes.push_back(byte);
    }

    // Find the first "?"
    for (int i = 0; i < bytes.size(); ++i) {
        if (bytes[i] == "?") {
            return i;
        }
    }

    return -1;  // Not found
}

uint32_t FindHeapFunctionOffset(char* result, BYTE* dump, int wildCardIndex)
{
	uint32_t foundRelativeOffset = *(uint32_t*)(result + wildCardIndex);
	auto relativeOffset = ((uint32_t)result - (uint32_t)dump);
	uint32_t address = (uint32_t)relativeOffset + foundRelativeOffset + 7;

	return address;
}

uint32_t FindOffset(char* result, int wildCardIndex)
{
	return *(uint32_t*)(result + wildCardIndex);
}

ULONG64 GameHacker::FindSignature(const char* signature, uint64_t range_start, size_t size, bool heap_function, int PID)
{
	if (!this->dump)
	{
		this->dump = new BYTE[size];
		VMMDLL_MemReadEx(this->current_process.vHandle, PID, range_start, this->dump, size, 0, VMMDLL_FLAG_NOCACHE);
	}

	auto result = Scan((char*)signature, (char*)this->dump, size);

	int wildcardIndex = FindFirstWildcardByteIndex(signature);

	if (result)
	{
		return heap_function ? FindHeapFunctionOffset(result, this->dump, wildcardIndex) : FindOffset(result, wildcardIndex);
	}
	else
	{
		LOG("[-] Failed to find signature\n");
		delete[] this->dump;
		return 0;
	}
}

bool GameHacker::Write(uintptr_t address, void* buffer, size_t size) const
{
	if (!(address > 0x2000000 && address < 0x7FFFFFFFFFFF))
		return false;
	if (!VMMDLL_MemWrite(this->current_process.vHandle, -1, address, (PBYTE)buffer, size))
	{
		LOG("[!] Failed to write Memory at 0x%p\n", address);
		return false;
	}
	return true;
}

bool GameHacker::Write(uintptr_t address, void* buffer, size_t size, int pid) const
{
	if (!(address > 0x2000000 && address < 0x7FFFFFFFFFFF))
		return false;
	if (!VMMDLL_MemWrite(this->current_process.vHandle, pid, address, (PBYTE)buffer, size))
	{
		LOG("[!] Failed to write Memory at 0x%p\n", address);
		return false;
	}
	return true;
}

bool GameHacker::Read(uintptr_t address, void* buffer, size_t size) const
{
	if (!VMMDLL_MemReadEx(this->current_process.vHandle, this->current_process.PID, address, (PBYTE)buffer, size, NULL, VMMDLL_FLAG_NOCACHE))
	{
		LOG("[!] Failed to read Memory at 0x%p\n", address);
		return false;
	}

	return true;
}

bool GameHacker::Read(uintptr_t address, void* buffer, size_t size, int pid) const
{
	if (!VMMDLL_MemReadEx(this->current_process.vHandle, pid, address, (PBYTE)buffer, size, NULL, VMMDLL_FLAG_NOCACHE))
	{
		LOG("[!] Failed to read Memory at 0x%p\n", address);
		return false;
	}

	return true;
}

VMMDLL_SCATTER_HANDLE GameHacker::CreateScatterHandle()
{
	VMMDLL_SCATTER_HANDLE ScatterHandle = VMMDLL_Scatter_Initialize(this->current_process.vHandle, this->current_process.PID, VMMDLL_FLAG_NOCACHE);
	if (!ScatterHandle)
		LOG("[!] Failed to create scatter handle\n");
	return ScatterHandle;
}

VMMDLL_SCATTER_HANDLE GameHacker::CreateScatterHandle(int pid)
{
	VMMDLL_SCATTER_HANDLE ScatterHandle = VMMDLL_Scatter_Initialize(this->current_process.vHandle, pid, VMMDLL_FLAG_NOCACHE);
	if (!ScatterHandle)
		LOG("[!] Failed to create scatter handle\n");
	return ScatterHandle;
}

void GameHacker::CloseScatterHandle(VMMDLL_SCATTER_HANDLE handle)
{
	VMMDLL_Scatter_CloseHandle(handle);
}

void GameHacker::AddScatterReadRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t address, void* buffer, size_t size)
{
	DWORD memoryPrepared = NULL;
	if (!VMMDLL_Scatter_PrepareEx(handle, address, size, (PBYTE)buffer, &memoryPrepared))
	{
		LOG("[!] Failed to prepare scatter read at 0x%p\n", address);
	}
}

void GameHacker::AddScatterWriteRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t address, void* buffer, size_t size)
{
	if (!(address > 0x2000000 && address < 0x7FFFFFFFFFFF))
		return;
	if (!VMMDLL_Scatter_PrepareWrite(handle, address, (PBYTE)buffer, size))
	{
		LOG("[!] Failed to prepare scatter write at 0x%p\n", address);
	}
}
void GameHacker::ExecuteScatterWrite(VMMDLL_SCATTER_HANDLE handle)
{

	if (!VMMDLL_Scatter_Execute(handle))
	{
		//LOG("[-] Failed to Execute Scatter Read\n");
	}
	//Clear after using it
	if (!VMMDLL_Scatter_Clear(handle, this->current_process.PID, VMMDLL_FLAG_NOCACHE))
	{
		LOG("[-] Failed to clear Scatter\n");
	}
}
void GameHacker::ExecuteScatterRead(VMMDLL_SCATTER_HANDLE handle)
{
	if (!VMMDLL_Scatter_ExecuteRead(handle))
	{
		//LOG("[-] Failed to Execute Scatter Read\n");
	}
	//Clear after using it
	if (!VMMDLL_Scatter_Clear(handle, this->current_process.PID, VMMDLL_FLAG_NOCACHE))
	{
		LOG("[-] Failed to clear Scatter\n");
	}
}
void GameHacker::ExecuteReadScatter(VMMDLL_SCATTER_HANDLE handle, int pid)
{
	if (pid == 0)
		pid = this->current_process.PID;

	if (!VMMDLL_Scatter_ExecuteRead(handle))
	{
		//LOG("[-] Failed to Execute Scatter Read\n");
	}
	//Clear after using it
	if (!VMMDLL_Scatter_Clear(handle, pid, VMMDLL_FLAG_NOCACHE))
	{
		LOG("[-] Failed to clear Scatter\n");
	}
}

void GameHacker::ExecuteWriteScatter(VMMDLL_SCATTER_HANDLE handle, int pid)
{
	if (pid == 0)
		pid = this->current_process.PID;

	if (!VMMDLL_Scatter_Execute(handle))
	{
		//LOG("[-] Failed to Execute Scatter Read\n");
	}
	//Clear after using it
	if (!VMMDLL_Scatter_Clear(handle, pid, VMMDLL_FLAG_NOCACHE))
	{
		LOG("[-] Failed to clear Scatter\n");
	}
}

std::string GameHacker::ReadString(uintptr_t address, size_t length) const
{
	if (address == 0 || length == 0)
		return {};

	// +1 for null-terminator
	std::vector<char> buffer(length + 1, '\0');

	// Call our existing Read(...) to copy from game memory
	if (!Read(address, buffer.data(), length))
	{
		std::cerr << "[!] Failed to read string at 0x" << std::hex << address << std::endl;
		return {};
	}

	// Now we have a null-terminated ASCII string in 'buffer'
	return std::string(buffer.data());
}