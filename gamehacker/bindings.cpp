#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "GameHacker.h"

namespace py = pybind11;

PYBIND11_MODULE(gamehacker, m)
{
    m.doc() = "Python DMA C++ library for read/writing game memory";

    py::class_<GameHacker::CurrentProcessInformation>(m, "CurrentProcessInformation")
    .def(py::init<>())
    .def_readonly("PID", &GameHacker::CurrentProcessInformation::PID)
    .def_readonly("base_address", &GameHacker::CurrentProcessInformation::base_address)
    .def_readonly("base_size", &GameHacker::CurrentProcessInformation::base_size)
    .def_readonly("process_name", &GameHacker::CurrentProcessInformation::process_name);

    py::class_<GameHacker>(m, "GameHacker")
    .def(py::init<>())
    .def_readonly_static("current_process_info", &GameHacker::current_process)
    .def("init_fpga", &GameHacker::InitFPGA, "Initialises the dma object")
    .def("close", &GameHacker::Close)
    .def("get_pid_from_name", &GameHacker::GetPidFromName)
    .def("get_pid_list_from_name", &GameHacker::GetPidListFromName)
    .def("get_module_list", &GameHacker::GetModuleList)
    .def("get_export_table_address", &GameHacker::GetExportTableAddress)
    .def("get_import_table_address", &GameHacker::GetImportTableAddress)
    .def("fix_cr3", &GameHacker::FixCr3)
    .def("virt_to_phys", [](GameHacker& self, uint64_t va) {
        uint64_t pa = 0;
        bool result = self.VirtToPhys(va, pa);
        return py::make_tuple(result, pa);
    })
    .def("dump_memory", &GameHacker::DumpMemory)
    .def("find_signature", &GameHacker::FindSignature)
    
    .def("write", [](GameHacker& self, uintptr_t address, py::bytes buffer, const std::string& format) {
        std::string str = buffer;
        if (!format.empty()) {
            // Serialize the data using the provided format
            py::module struct_module = py::module::import("struct");
            py::object pack = struct_module.attr("pack");
            py::bytes packed_data = pack(format, buffer);
            str = std::string(packed_data);
        }
        return self.Write(address, (void*)str.data(), str.size());
    })
    
    .def("write_with_pid", [](GameHacker& self, uintptr_t address, py::bytes buffer, const std::string& format, int pid) {
        std::string str = buffer;
        if (!format.empty()) {
            // Serialize the data using the provided format
            py::module struct_module = py::module::import("struct");
            py::object pack = struct_module.attr("pack");
            py::bytes packed_data = pack(format, buffer);
            str = std::string(packed_data);
        }
        return self.Write(address, (void*)str.data(), str.size(), pid);
    })
    
    // Regular read method using lambda
    .def("read", [](GameHacker& self, uintptr_t address, size_t size) {
        std::vector<char> buffer(size);

        bool success = self.Read(address, buffer.data(), size);
        if (success) {
            return py::bytes(buffer.data(), size);
        }
    })
    
    // Read with PID using lambda
    .def("read_with_pid", [](GameHacker& self, uintptr_t address, size_t size, int pid) {
        std::vector<char> buffer(size);

        bool success = self.Read(address, buffer.data(), size, pid);
        if (success) {
            return py::bytes(buffer.data(), size);
        }
    })
    
    .def("read_string", &GameHacker::ReadString)
    
    // Scatter methods using lambdas instead of overload_cast
    .def("create_scatter_handle", [](GameHacker& self) {
        return self.CreateScatterHandle();
    })
    .def("create_scatter_handle_with_pid", [](GameHacker& self, int pid) {
        return self.CreateScatterHandle(pid);
    })
    .def("close_scatter_handle", &GameHacker::CloseScatterHandle)
    
    // Scatter read/write with lambdas
    .def("add_scatter_read_request", [](GameHacker& self, VMMDLL_SCATTER_HANDLE handle, uint64_t address, size_t size) {
        std::vector<char> buffer(size);

        self.AddScatterReadRequest(handle, address, buffer.data(), size);
        return py::bytes(buffer.data());
    })
    
    .def("add_scatter_write_request", [](GameHacker& self, VMMDLL_SCATTER_HANDLE handle, uint64_t address, py::bytes buffer, const std::string& format) {
        std::string str = buffer;
        if (!format.empty()) {
            // Serialize the data using the provided format
            py::module struct_module = py::module::import("struct");
            py::object pack = struct_module.attr("pack");
            py::bytes packed_data = pack(format, buffer);
            str = std::string(packed_data);
        }
        self.AddScatterWriteRequest(handle, address, (void*)str.data(), str.size());
    })
    
    // Execute scatter methods
    .def("execute_read_scatter", [](GameHacker& self, VMMDLL_SCATTER_HANDLE handle, int pid) {
        self.ExecuteReadScatter(handle, pid);
    })
    
    .def("execute_write_scatter", [](GameHacker& self, VMMDLL_SCATTER_HANDLE handle, int pid) {
        self.ExecuteWriteScatter(handle, pid);
    })
    
    .def("execute_scatter_read", &GameHacker::ExecuteScatterRead)
    .def("execute_scatter_write", &GameHacker::ExecuteScatterWrite);
}