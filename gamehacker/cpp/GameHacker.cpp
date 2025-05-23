#include "pch.h"
#include "GameHacker.h"
#include <iostream>
#include <thread>
#include <Python.h>

std::string GetPydPath() {
    PyObject* sys_module = PyImport_ImportModule("sys");
    if (!sys_module) {
        THROW("[!] Failed to import sys module\n");
        return "";
    }

    PyObject* modules_dict = PyObject_GetAttrString(sys_module, "modules");
    Py_DECREF(sys_module);
    if (!modules_dict) {
        THROW("[!] Failed to get sys.modules\n");
        return "";
    }

    PyObject* gamehacker_module = PyDict_GetItemString(modules_dict, "gamehacker");
    Py_DECREF(modules_dict);
    if (!gamehacker_module) {
        THROW("[!] Failed to find gamehacker module in sys.modules\n");
        return "";
    }

    PyObject* file_attr = PyObject_GetAttrString(gamehacker_module, "__file__");
    if (!file_attr) {
        THROW("[!] Failed to get __file__ attribute of gamehacker module\n");
        return "";
    }

    const char* file_path = PyUnicode_AsUTF8(file_attr);
    Py_DECREF(file_attr);

    if (!file_path) {
        THROW("[!] Failed to convert __file__ to string\n");
        return "";
    }

    return std::string(file_path);
}

std::string GetPyScriptPath() {
    PyObject* globals = PyEval_GetGlobals();
    if (globals) {
        PyObject* pyFileName = PyDict_GetItemString(globals, "__file__");
        if (pyFileName && PyUnicode_Check(pyFileName)) {
            std::string script_path = PyUnicode_AsUTF8(pyFileName);
            size_t pos = script_path.find_last_of("\\/");
            return script_path.substr(0, ++pos);
        }
    }
    return "";
}

GameHacker::GameHacker() {
    std::filesystem::path libs_path;

    // Get the path of the .pyd file
    std::string pyd_path = GetPydPath();
    if (!pyd_path.empty()) {
        libs_path = std::filesystem::path(pyd_path).parent_path();
    } else {
        THROW("[!] Failed to determine .pyd location, falling back to default paths\n");
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
        THROW("[!] Could not load required libraries\n");
    }
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
        THROW("[!] Failed to open VMM handle\n");
        return false;
    }

    PVMMDLL_MAP_PHYSMEM pPhysMemMap = NULL;

    if (!VMMDLL_Map_GetPhysMem(handle, &pPhysMemMap))
    {
        THROW("[!] Failed to get physical memory map\n");
        VMMDLL_Close(handle);
        return false;
    }

    if (pPhysMemMap->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION)
    {
        THROW("[!] invalid VMM map version\n");
        VMMDLL_MemFree(pPhysMemMap);
        VMMDLL_Close(handle);
        return false;
    }

    if (pPhysMemMap->cMap == 0)
	{
		THROW("[!] Failed to get physical memory map\n");
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

    if ((qwVersionMajor >= 4) && ((qwVersionMajor >= 5) || (qwVersionMinor >= 7)))
	{
		HANDLE handle;
		LC_CONFIG config = { .dwVersion = LC_CONFIG_VERSION, .szDevice = "existing"};
		handle = LcCreate(&config);
		if (!handle)
		{
			THROW("[!] Failed to create FPGA device\n");
			return false;
		}

		LcCommand(handle, LC_CMD_FPGA_CFGREGPCIE_MARKWR | 0x002, 4, reinterpret_cast<PBYTE>(&abort2), NULL, NULL);
		LcClose(handle);
	}

	return true;
}

bool GameHacker::InitFPGA(std::string process_name, bool memMap, bool debug)
{

    if (!DMA_INITIALIZED)
    {
        LOG("[...] VMM inizializing...\n");
    reInitDma:
        LPCSTR args[] = {const_cast<LPCSTR>(""), const_cast<LPCSTR>("-device"), const_cast<LPCSTR>("fpga://algo=0"), const_cast<LPCSTR>(""), const_cast<LPCSTR>(""), const_cast<LPCSTR>(""), const_cast<LPCSTR>("")};
        DWORD argc = 3;
    
        if (debug)
        {
            args[argc++] = const_cast<LPCSTR>("-v");
            args[argc++] = const_cast<LPCSTR>("-printf");
        }

        if (memMap)
        {
            auto temp_path = std::filesystem::current_path();
            auto path = temp_path / "mmap.txt";
            bool dumped = false;

            if (!std::filesystem::exists(path))
            {
                dumped = this->DumpMemoryMap(args, argc);
            }
            else
            {
                dumped = true;
            }

			if (!dumped)
			{
				LOG("[!] ERROR: Could not dump memory map!\n");
				LOG("[!] Defaulting to no memory map!\n");
			}
			else
			{
				LOG("[+] Dumped memory map!\n");
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
                goto reInitDma;
            }

            THROW("[!] Initialization failed! Is the DMA in use or disconnected?\n");
			return false;
        }

        ULONG64 FPGA_ID = 0, DEVICE_ID = 0;

        VMMDLL_ConfigGet(this->current_process.vHandle, LC_OPT_FPGA_FPGA_ID, &FPGA_ID);
        VMMDLL_ConfigGet(this->current_process.vHandle, LC_OPT_FPGA_DEVICE_ID, &DEVICE_ID);
        
        if (!this->SetFPGA())
        {
            THROW("[!] Could not set FPGA\n");
            VMMDLL_Close(this->current_process.vHandle);
            return false;
        }

        DMA_INITIALIZED = TRUE;
    }
    else
    {
        LOG("[+] DMA already initialized\n");
    }

    if (PROCESS_INITIALIZED)
    {
        LOG("[+] Process already initialized\n");
        return true;
    }

    this->current_process.PID = this->GetPidFromName(process_name);
	if (!this->current_process.PID)
	{
		THROW("[!] Could not get PID from name!\n");
		return false;
	}

	this->GetProcessInfo();

	this->current_process.process_name = process_name;

	LOG("[+] Process information of %s\n", process_name.c_str());
	LOG("  - PID: %i\n", this->current_process.PID);
	LOG("  - Base Address: 0x%p\n", this->current_process.base_address);
	LOG("  - Base Size: 0x%p\n", this->current_process.base_size);

	PROCESS_INITIALIZED = TRUE;

	if (!this->dump)
	{
		this->dump = new BYTE[this->current_process.base_size];
		VMMDLL_MemReadEx(this->current_process.vHandle, this->current_process.PID, this->current_process.base_address, this->dump, this->current_process.base_size, 0, VMMDLL_FLAG_NOCACHE);
	}

	return true;
}

DWORD GameHacker::GetPidFromName(std::string process_name)
{
	DWORD pid = 0;
	VMMDLL_PidGetFromName(this->current_process.vHandle, (LPSTR)process_name.c_str(), &pid);

	if (!pid)
		THROW("[!] Failed to get executable PID\n");

	return pid;
}

std::vector<int> GameHacker::GetPidListFromName(std::string name)
{
	PVMMDLL_PROCESS_INFORMATION process_info = NULL;
	DWORD total_processes = 0;
	std::vector<int> list = { };

	if (!VMMDLL_ProcessGetInformationAll(this->current_process.vHandle, &process_info, &total_processes))
	{
		THROW("[!] Failed to get process list\n");
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
		THROW("[!] Failed to get module list\n");
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
		THROW("[!] Failed to get process information\n");
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
		THROW("[!] Failed to get Export Table\n");
		return 0;
	}

	if (eat_map->dwVersion != VMMDLL_MAP_EAT_VERSION)
	{
		VMMDLL_MemFree(eat_map);
		eat_map = NULL;
		THROW("[!] Invalid VMM Map Version\n");
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
		THROW("[!] Failed to get Import Table\n");
		return 0;
	}

	if (iat_map->dwVersion != VMMDLL_MAP_IAT_VERSION)
	{
		VMMDLL_MemFree(iat_map);
		iat_map = NULL;
		THROW("[!] Invalid VMM Map Version\n");
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

bool GameHacker::FixCr3(bool cache_pml4)
{
	PVMMDLL_MAP_MODULEENTRY module_entry;
	bool result = VMMDLL_Map_GetModuleFromNameU(this->current_process.vHandle, this->current_process.PID, (LPSTR)this->current_process.process_name.c_str(), &module_entry, NULL);
	if (result)
	{
		//return true; //PREVENTS USING CACHED PML4
	}

	if (!VMMDLL_InitializePlugins(this->current_process.vHandle))
	{
		THROW("[-] Failed VMMDLL_InitializePlugins call\n");
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
			if (cache_pml4)
			{
				static ULONG64 pml4_first[512];
				static ULONG64 pml4_second[512];
				DWORD readsize;
	
	
				if (!VMMDLL_MemReadEx(this->current_process.vHandle, -1, dtb, reinterpret_cast<PBYTE>(pml4_first), sizeof(pml4_first), (PDWORD)&readsize,
					VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
					THROW("[!] Failed to read PML4 the first time\n");
					return false;
				}
	
				if (!VMMDLL_MemReadEx(this->current_process.vHandle, -1, dtb, reinterpret_cast<PBYTE>(pml4_second), sizeof(pml4_second), (PDWORD)&readsize,
					VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_ZEROPAD_ON_FAIL | VMMDLL_FLAG_NOPAGING_IO)) {
					THROW("[!] Failed to read PML4 the second time\n");
					return false;
				}
	
				if (memcmp(pml4_first, pml4_second, sizeof(pml4_first)) != 0) {
					THROW("[!] PML4 mismatch between reads\n");
					return false;
				}
	
				VMMDLL_MemReadEx((VMM_HANDLE)-666, 333, (ULONG64)pml4_first, 0, 0, 0, 0);
	
				VMMDLL_ConfigSet(this->current_process.vHandle, VMMDLL_OPT_PROCESS_DTB | this->current_process.PID, 666);
	
				LOG("[+] Cache initialization complete\n");

				return true;
			}

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

	THROW("[!] VMMDLL_MemVirt2Phys failed\n");
	return false;
}

bool GameHacker::DumpMemory()
{
	LOG("Dumping memory of process %s\n", this->current_process.process_name.c_str());

	if (!this->dump)
	{
		this->dump = new BYTE[this->current_process.base_size];
		VMMDLL_MemReadEx(this->current_process.vHandle, this->current_process.PID, this->current_process.base_address, this->dump, this->current_process.base_size, 0, VMMDLL_FLAG_NOCACHE);
	}

	auto pdos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->dump);

	if (!pdos_header->e_lfanew)
	{
		THROW("[!] Failed to get dos header from buffer\n");
		return false;
	}

	if (pdos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		THROW("[!] Invalid dos header signature\n");
		return false;
	}

	auto pnt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(this->dump + pdos_header->e_lfanew);

	if (!pnt_header)
	{
		THROW("[!] Failed to read nt header from buffer\n");
		return false;
	}

    if (pnt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        THROW("[!] Invalid nt header signature from readed nt header\n");
        return false;
    }

    auto poptional_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&pnt_header->OptionalHeader);

    if (!poptional_header)
    {
        THROW("[!] Failed to read optional header from buffer\n");
        return false;
    }

    int i = 0;
    unsigned int section_offset = poptional_header->SizeOfHeaders;

    for (
        PIMAGE_SECTION_HEADER psection_header = IMAGE_FIRST_SECTION(pnt_header);
        i < pnt_header->FileHeader.NumberOfSections;
        i++, psection_header++
        )
    {
        psection_header->Misc.VirtualSize = psection_header->SizeOfRawData;

        memcpy(this->dump + section_offset, psection_header, sizeof(IMAGE_SECTION_HEADER));
        section_offset += sizeof(IMAGE_SECTION_HEADER);

        if (!Read(
            poptional_header->ImageBase + psection_header->VirtualAddress,
            this->dump + psection_header->PointerToRawData,
            psection_header->SizeOfRawData
        ))
        {
            THROW("[!] Failed to read buffer from headers\n");
            return false;
        }
    }

    char FileName[MAX_PATH];
    sprintf_s(FileName, "%s%s_dump.exe", GetPyScriptPath().c_str(), this->current_process.process_name.c_str());
    
    std::ofstream Dump(FileName, std::ios::binary);
    Dump.write((char*)this->dump, this->current_process.base_size);
    Dump.close();

    LOG("[>] Dumped successfully to %s\n", FileName);

    return true;
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
	char pattern[10000];
	char mask[10000];
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

ULONG64 GameHacker::FindSignature(const char* signature, size_t size, bool heap_function)
{
	auto result = Scan((char*)signature, (char*)this->dump, size);

	int wildcardIndex = FindFirstWildcardByteIndex(signature);

	if (result)
	{
		return heap_function ? FindHeapFunctionOffset(result, this->dump, wildcardIndex) : FindOffset(result, wildcardIndex);
	}
	else
	{
		THROW("[-] Failed to find signature\n");
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
		THROW("[!] Failed to create scatter handle\n");
	return ScatterHandle;
}

VMMDLL_SCATTER_HANDLE GameHacker::CreateScatterHandle(int pid)
{
	VMMDLL_SCATTER_HANDLE ScatterHandle = VMMDLL_Scatter_Initialize(this->current_process.vHandle, pid, VMMDLL_FLAG_NOCACHE);
	if (!ScatterHandle)
		THROW("[!] Failed to create scatter handle\n");
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