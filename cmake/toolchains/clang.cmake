# Clang toolchain for the "clang" preset.
# Windows uses clang-cl (MSVC-compatible). Other hosts use clang and clang++.

if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64|ARM64EC")
	set(_dns_llvm_arch ARM64)
else()
	set(_dns_llvm_arch x64)
endif()

function(_dns_first_existing out_var)
	foreach(_dns_candidate IN LISTS ARGN)
		if(EXISTS "${_dns_candidate}")
			set(${out_var} "${_dns_candidate}" PARENT_SCOPE)
			return()
		endif()
	endforeach()
	set(${out_var} "" PARENT_SCOPE)
endfunction()

function(_dns_find_ninja out_var)
	find_program(_dns_ninja_on_path ninja)
	if(_dns_ninja_on_path)
		set(${out_var} "${_dns_ninja_on_path}" PARENT_SCOPE)
		return()
	endif()

	set(_dns_ninja_globs
		"C:/Microsoft Visual Studio/2026/*/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe"
		"C:/Program Files/Microsoft Visual Studio/18/*/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe"
		"C:/Program Files/Microsoft Visual Studio/2022/*/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe"
		"C:/Program Files (x86)/Microsoft Visual Studio/2022/*/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe"
	)
	foreach(_dns_glob IN LISTS _dns_ninja_globs)
		file(GLOB _dns_ninja_hits "${_dns_glob}")
		if(_dns_ninja_hits)
			list(GET _dns_ninja_hits 0 _dns_ninja_hit)
			set(${out_var} "${_dns_ninja_hit}" PARENT_SCOPE)
			return()
		endif()
	endforeach()
	set(${out_var} "" PARENT_SCOPE)
endfunction()

if(CMAKE_HOST_WIN32)
	set(_dns_clang_candidates "")
	foreach(_dns_year IN ITEMS 2026 2022)
		foreach(_dns_edition IN ITEMS Enterprise Professional Community BuildTools)
			foreach(_dns_root IN ITEMS
				"C:/Microsoft Visual Studio/${_dns_year}/${_dns_edition}"
				"C:/Program Files/Microsoft Visual Studio/${_dns_year}/${_dns_edition}"
				"C:/Program Files (x86)/Microsoft Visual Studio/${_dns_year}/${_dns_edition}")
				list(APPEND _dns_clang_candidates
					"${_dns_root}/VC/Tools/Llvm/${_dns_llvm_arch}/bin/clang-cl.exe")
				if(_dns_llvm_arch STREQUAL "x64")
					list(APPEND _dns_clang_candidates
						"${_dns_root}/VC/Tools/Llvm/bin/clang-cl.exe")
				endif()
			endforeach()
		endforeach()
	endforeach()
	list(APPEND _dns_clang_candidates
		"C:/Program Files/LLVM/bin/clang-cl.exe"
		"C:/Program Files/LLVM/bin/clang.exe")

	find_program(_dns_clang_on_path NAMES clang-cl clang)
	if(_dns_clang_on_path)
		list(INSERT _dns_clang_candidates 0 "${_dns_clang_on_path}")
	endif()

	_dns_first_existing(DNS_CLANG_C ${_dns_clang_candidates})
	set(DNS_CLANG_CXX "${DNS_CLANG_C}")
else()
	find_program(DNS_CLANG_C clang)
	find_program(DNS_CLANG_CXX clang++)
endif()

if(NOT DNS_CLANG_C OR NOT DNS_CLANG_CXX)
	message(FATAL_ERROR
		"The clang preset needs Clang.\n"
		"On Windows, install Clang (clang-cl) or the Visual Studio C++ Clang tools.\n"
		"On Linux and macOS, install clang and clang++.")
endif()

set(DNS_CLANG_C "${DNS_CLANG_C}" CACHE FILEPATH "Clang C compiler" FORCE)
set(DNS_CLANG_CXX "${DNS_CLANG_CXX}" CACHE FILEPATH "Clang C++ compiler" FORCE)
set(CMAKE_C_COMPILER "${DNS_CLANG_C}" CACHE FILEPATH "C compiler" FORCE)
set(CMAKE_CXX_COMPILER "${DNS_CLANG_CXX}" CACHE FILEPATH "C++ compiler" FORCE)

if(CMAKE_GENERATOR MATCHES "Ninja")
	_dns_find_ninja(_dns_ninja)
	if(NOT _dns_ninja)
		message(FATAL_ERROR
			"The clang preset needs Ninja. Install Ninja and add it to PATH, "
			"or install the CMake tools that ship with Visual Studio.")
	endif()
	set(CMAKE_MAKE_PROGRAM "${_dns_ninja}" CACHE FILEPATH "Ninja build tool" FORCE)
endif()
