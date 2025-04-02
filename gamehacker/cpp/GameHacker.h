#ifndef GAMEHACKER_H
#define GAMEHACKER_H

#include "pch.h"

class GameHacker
{
public:

    GameHacker();
    ~GameHacker();

    struct CurrentProcessInformation
    {
        VMM_HANDLE vHandle;
        int PID = 0;
        size_t base_address = 0;
        size_t base_size = 0;
        std::string process_name = "";
    };

    static inline CurrentProcessInformation current_process { };

    bool InitFPGA(std::string process_name, bool memMap = true, bool debug = false);
	void Close();

    DWORD GetPidFromName(std::string process_name);
    std::vector<int> GetPidListFromName(std::string name);
    std::vector<std::string> GetModuleList(std::string process_name);
	void GetProcessInfo();
    uintptr_t GetExportTableAddress(std::string import, std::string process, std::string module);
    uintptr_t GetImportTableAddress(std::string import, std::string process, std::string module);
    bool FixCr3(bool cache_pml4 = false);
    bool VirtToPhys(uint64_t va, uint64_t& pa);
    bool DumpMemory();
    ULONG64 FindSignature(const char* signature, uint64_t range_start, size_t size, bool heap_function, int PID);

    bool Write(uintptr_t address, void* buffer, size_t size) const;
	bool Write(uintptr_t address, void* buffer, size_t size, int pid) const;

	bool Read(uintptr_t address, void* buffer, size_t size) const;
	bool Read(uintptr_t address, void* buffer, size_t size, int pid) const;

	std::string ReadString(uintptr_t address, size_t length) const;

	VMMDLL_SCATTER_HANDLE CreateScatterHandle();
	VMMDLL_SCATTER_HANDLE CreateScatterHandle(int pid);

	void CloseScatterHandle(VMMDLL_SCATTER_HANDLE handle);

	void AddScatterReadRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t address, void* buffer, size_t size);
	void AddScatterWriteRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t address, void* buffer, size_t size);
	template <typename T>
	bool AddScatterWriteRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t addr, T value) const
	{
		bool ret = !VMMDLL_Scatter_PrepareWrite(handle, addr, reinterpret_cast<PBYTE>(&value), sizeof(value));
		if (!ret)
		{
			//	LOG("failed to prepare scatter write at 0x%p\n", addr);
		}
		return ret;
	}

	void ExecuteReadScatter(VMMDLL_SCATTER_HANDLE handle, int pid = 0);
	void ExecuteWriteScatter(VMMDLL_SCATTER_HANDLE handle, int pid = 0);
	void ExecuteScatterRead(VMMDLL_SCATTER_HANDLE handle);
	void ExecuteScatterWrite(VMMDLL_SCATTER_HANDLE handle);

private:
    struct DmaModules
    {
        HMODULE VMM = nullptr;
        HMODULE FTD3XX = nullptr;
        HMODULE LEECHCORE = nullptr;
    };

    static inline DmaModules modules { };

    static inline BOOLEAN DMA_INITIALIZED = FALSE;
    static inline BOOLEAN PROCESS_INITIALIZED = FALSE;

    std::unordered_map<std::wstring, ULONG64> Modules;

    BYTE* dump;
    bool DumpMemoryMap(LPCSTR args[], int argc);
    bool SetFPGA();
};

#endif