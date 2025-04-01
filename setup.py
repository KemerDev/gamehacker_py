import os
import pybind11
from pathlib import Path
from setuptools import setup, find_packages
from pybind11.setup_helpers import Pybind11Extension, build_ext

# Base directory (always use forward slashes)
base_dir = Path(__file__).parent

# ===== Extension Module Configuration =====
ext_name = "gamehacker"  # Output will be gamehacker.pyd (Windows) or gamehacker.so (Unix)

sources = [
    "gamehacker/bindings.cpp",
    "gamehacker/cpp/GameHacker.cpp",
]

include_dirs = [
    "gamehacker/includes",
    "gamehacker/cpp",
    pybind11.get_include(),
]

library_dirs = [
    "gamehacker/libs",
    "gamehacker/dlls",
]

# Libraries (check existence)
libraries = []
for lib in ["leechcore", "vmm"]:
    lib_path = base_dir / "gamehacker" / "libs" / f"{lib}.lib"
    if lib_path.exists():
        libraries.append(lib)
    else:
        print(f"Warning: Library not found - {lib_path}")

# Windows-specific settings
extra_compile_args = []
if os.name == 'nt':
    libraries.extend(["user32", "kernel32", "advapi32", "shell32"])
    extra_compile_args.extend([
        '/std:c++20',
        '/permissive-',
        '/Zc:templateScope',
        '/bigobj'
    ])

ext_modules = [
    Pybind11Extension(
        ext_name,
        sources=sources,
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=libraries,
        define_macros=[
            ('VERSION_INFO', '"0.1.0"'),
            ('NOMINMAX', '1'),
            ('_HAS_EXCEPTIONS', '1'),
            ('VMM_EXPORT', ''),
            ('LEECHCORE_EXPORT', '')
        ],
        extra_compile_args=extra_compile_args,
        cxx_std=20
    )
]

import shutil

class BuildWithDLLs(build_ext):
    def run(self):
        super().run()
        
        # Get the .pyd output path
        pyd_path = self.get_ext_fullpath('gamehacker')
        
        # 1. Ensure .pyd goes to package folder
        dest_dir = os.path.join(self.build_lib, 'gamehacker')
        os.makedirs(dest_dir, exist_ok=True)
        shutil.move(pyd_path, os.path.join(dest_dir, os.path.basename(pyd_path)))
        
        # 2. Copy DLLs to same folder
        dlls = ['vmm.dll', 'leechcore.dll', 'FTD3XX.dll']
        for dll in dlls:
            src = os.path.join('gamehacker', 'dlls', dll)
            if os.path.exists(src):
                shutil.copy(src, dest_dir)
         
        src = os.path.join("gamehacker", "db", "info.db")
        if os.path.exists(src):
            shutil.copy(src, dest_dir)

# ===== Package Data =====

package_data = {
    ext_name: [
        "*.dll",
        "*.pyd",
        "*.pyi"
    ]
}

# ===== Wheel Configuration =====
setup(
    name="gamehacker",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Python DMA C++ library for game memory access",
    long_description=open(base_dir / "README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/gamehacker",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
    ],
    packages=find_packages(),
    package_data=package_data,
    exclude_package_data={
        "gamehacker": [
            "*.cpp",
        ]
    },
    include_package_data=True,
    ext_modules=ext_modules,
    cmdclass={'build_ext': BuildWithDLLs},
    zip_safe=False,
    python_requires=">=3.7",
    install_requires=["pybind11>=2.6.0"],
    setup_requires=["pybind11>=2.6.0"],
)