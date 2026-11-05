if(NOT DEFINED LIB_BIN OR NOT DEFINED LIB_ROOT OR NOT DEFINED DLL_LIST_FILE)
	message(FATAL_ERROR "CheckTechnitiumLibrary.cmake requires LIB_BIN, LIB_ROOT, and DLL_LIST_FILE.")
endif()

file(READ "${DLL_LIST_FILE}" _dns_dll_text)
string(STRIP "${_dns_dll_text}" _dns_dll_text)
string(REPLACE "\n" ";" _dns_dlls "${_dns_dll_text}")
set(_dns_missing "")
foreach(_dns_dll IN LISTS _dns_dlls)
	if(_dns_dll STREQUAL "")
		continue()
	endif()
	if(NOT EXISTS "${LIB_BIN}/${_dns_dll}")
		list(APPEND _dns_missing "${LIB_BIN}/${_dns_dll}")
	endif()
endforeach()

if(_dns_missing)
	string(JOIN "\n  " _dns_missing_text ${_dns_missing})
	message(FATAL_ERROR
		"TechnitiumLibrary assemblies were not found:\n  ${_dns_missing_text}\n"
		"Clone https://github.com/TechnitiumSoftware/TechnitiumLibrary so it sits next to this repository "
		"(expected ${LIB_ROOT}), or configure with -DTECHNITIUM_LIBRARY_DIR=<checkout>. "
		"Those projects write their assemblies to ${LIB_BIN}.")
endif()
