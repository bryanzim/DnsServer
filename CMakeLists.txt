cmake_minimum_required(VERSION 4.2)

# Technitium DNS Server is C# on .NET 11. Both presets compile it with the
# .NET SDK. The preset selects the native toolchain CMake configures:
#   vs2026  ->  Visual Studio 18 2026 generator (MSVC toolset)
#   clang   ->  Ninja + Clang (clang-cl on Windows)
project(TechnitiumDnsServer
	VERSION 15.6.2
	DESCRIPTION "Technitium DNS Server"
	LANGUAGES NONE
)

set(DNS_TOOLCHAIN "" CACHE STRING "Build toolchain: vs2026 or clang")
set_property(CACHE DNS_TOOLCHAIN PROPERTY STRINGS vs2026 clang)

if(DNS_TOOLCHAIN STREQUAL "vs2026")
	if(NOT CMAKE_GENERATOR STREQUAL "Visual Studio 18 2026")
		message(FATAL_ERROR
			"DNS_TOOLCHAIN=vs2026 requires the Visual Studio 18 2026 generator.\n"
			"Configure with: cmake --preset vs2026")
	endif()
elseif(DNS_TOOLCHAIN STREQUAL "clang")
	if(NOT CMAKE_GENERATOR MATCHES "Ninja")
		message(FATAL_ERROR
			"DNS_TOOLCHAIN=clang requires the Ninja generator.\n"
			"Configure with: cmake --preset clang")
	endif()
	if(NOT DNS_CLANG_CXX OR NOT EXISTS "${DNS_CLANG_CXX}")
		message(FATAL_ERROR
			"DNS_TOOLCHAIN=clang requires cmake/toolchains/clang.cmake.\n"
			"Configure with: cmake --preset clang")
	endif()
	execute_process(
		COMMAND "${DNS_CLANG_CXX}" --version
		RESULT_VARIABLE _dns_clang_result
		OUTPUT_VARIABLE _dns_clang_version
		ERROR_VARIABLE _dns_clang_version
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_STRIP_TRAILING_WHITESPACE
	)
	if(NOT _dns_clang_result EQUAL 0)
		message(FATAL_ERROR "Clang failed to run: ${DNS_CLANG_CXX}")
	endif()
	string(REGEX REPLACE "[\r\n].*" "" _dns_clang_version "${_dns_clang_version}")
else()
	message(FATAL_ERROR
		"Set DNS_TOOLCHAIN to vs2026 or clang.\n"
		"  cmake --preset vs2026\n"
		"  cmake --preset clang")
endif()

find_program(DOTNET_EXECUTABLE dotnet REQUIRED)

set(TECHNITIUM_LIBRARY_DIR "${CMAKE_SOURCE_DIR}/../TechnitiumLibrary" CACHE PATH
	"TechnitiumLibrary checkout. Assemblies are read from its bin directory.")
cmake_path(ABSOLUTE_PATH TECHNITIUM_LIBRARY_DIR NORMALIZE OUTPUT_VARIABLE DNS_LIBRARY_ROOT)
cmake_path(SET DNS_LIBRARY_HINT_ROOT NORMALIZE "${CMAKE_SOURCE_DIR}/../TechnitiumLibrary")
if(NOT DNS_LIBRARY_ROOT STREQUAL DNS_LIBRARY_HINT_ROOT)
	message(WARNING
		"Project references load TechnitiumLibrary from ${DNS_LIBRARY_HINT_ROOT}/bin. "
		"TECHNITIUM_LIBRARY_DIR is ${DNS_LIBRARY_ROOT}. "
		"Place the checkout at ${DNS_LIBRARY_HINT_ROOT} so those HintPaths resolve.")
endif()
set(DNS_DOTNET_CONFIGURATION "$<IF:$<CONFIG:Debug>,Debug,Release>")

set(DNS_LIBRARY_DLLS
	TechnitiumLibrary.dll
	TechnitiumLibrary.ByteTree.dll
	TechnitiumLibrary.IO.dll
	TechnitiumLibrary.Net.dll
	TechnitiumLibrary.Security.OTP.dll
)
if(WIN32)
	list(APPEND DNS_LIBRARY_DLLS TechnitiumLibrary.Net.Firewall.dll)
endif()
string(JOIN "\n" DNS_LIBRARY_DLL_ARG ${DNS_LIBRARY_DLLS})
file(WRITE "${CMAKE_BINARY_DIR}/technitium-library-dlls.txt" "${DNS_LIBRARY_DLL_ARG}\n")

# HintPaths point at TechnitiumLibrary/bin. The firewall project emits that
# path only for Release, and its COM reference cannot be built by dotnet.
set(DNS_LIBRARY_CONFIGURATION Release)
set(DNS_MSBUILD_EXECUTABLE "")
if(WIN32)
	find_program(VSWHERE_EXECUTABLE vswhere
		HINTS "$ENV{ProgramFiles\(x86\)}/Microsoft Visual Studio/Installer")
	if(VSWHERE_EXECUTABLE)
		execute_process(
			COMMAND "${VSWHERE_EXECUTABLE}" -latest -products * -version "[18.0,19.0)"
				-requires Microsoft.Component.MSBuild
				-find "MSBuild\\**\\Bin\\MSBuild.exe"
			OUTPUT_VARIABLE _dns_msbuild_out
			OUTPUT_STRIP_TRAILING_WHITESPACE
			RESULT_VARIABLE _dns_msbuild_rc
		)
		if(NOT _dns_msbuild_rc EQUAL 0 OR NOT _dns_msbuild_out)
			execute_process(
				COMMAND "${VSWHERE_EXECUTABLE}" -latest -products * -requires Microsoft.Component.MSBuild
					-find "MSBuild\\**\\Bin\\MSBuild.exe"
				OUTPUT_VARIABLE _dns_msbuild_out
				OUTPUT_STRIP_TRAILING_WHITESPACE
				RESULT_VARIABLE _dns_msbuild_rc
			)
		endif()
		if(_dns_msbuild_rc EQUAL 0 AND _dns_msbuild_out)
			string(REGEX MATCH "^[^\r\n]+" DNS_MSBUILD_EXECUTABLE "${_dns_msbuild_out}")
		endif()
	endif()
	if(NOT DNS_MSBUILD_EXECUTABLE)
		unset(DNS_MSBUILD_EXECUTABLE)
		find_program(DNS_MSBUILD_EXECUTABLE MSBuild)
	endif()
endif()

set(_dns_firewall_project "${DNS_LIBRARY_ROOT}/TechnitiumLibrary.Net.Firewall/TechnitiumLibrary.Net.Firewall.csproj")
if(WIN32 AND EXISTS "${_dns_firewall_project}" AND NOT DNS_MSBUILD_EXECUTABLE)
	message(FATAL_ERROR
		"TechnitiumLibrary.Net.Firewall uses a COM reference, which dotnet build cannot compile. "
		"Install Visual Studio 2026 with MSBuild.")
endif()

if(NOT EXISTS "${DNS_LIBRARY_ROOT}/TechnitiumLibrary.sln" AND NOT EXISTS "${DNS_LIBRARY_ROOT}/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj")
	message(WARNING
		"TechnitiumLibrary was not found at ${DNS_LIBRARY_ROOT}. "
		"The build expects its assemblies in ${DNS_LIBRARY_ROOT}/bin.")
endif()

# Build the local master branch, then return that repo to the branch that was checked out.
# HintPaths read ../TechnitiumLibrary/bin, and that directory is gitignored, so the assemblies stay.
add_custom_target(technitium_library
	COMMAND ${CMAKE_COMMAND}
		-DLIB_ROOT=${DNS_LIBRARY_ROOT}
		-DDOTNET_EXECUTABLE=${DOTNET_EXECUTABLE}
		-DMSBUILD_EXECUTABLE=${DNS_MSBUILD_EXECUTABLE}
		-DCONFIGURATION=${DNS_LIBRARY_CONFIGURATION}
		-DSNAPSHOT_DIR=${CMAKE_BINARY_DIR}/technitium-library-bin
		-P ${CMAKE_SOURCE_DIR}/cmake/BuildTechnitiumLibrary.cmake
	COMMAND ${CMAKE_COMMAND}
		-DLIB_BIN=${DNS_LIBRARY_ROOT}/bin
		-DLIB_ROOT=${DNS_LIBRARY_ROOT}
		-DDLL_LIST_FILE=${CMAKE_BINARY_DIR}/technitium-library-dlls.txt
		-P ${CMAKE_SOURCE_DIR}/cmake/CheckTechnitiumLibrary.cmake
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	USES_TERMINAL
	VERBATIM
	COMMENT "Build TechnitiumLibrary master"
)

set(DNS_SERVER_PROJECTS "")
if(WIN32)
	list(APPEND DNS_SERVER_PROJECTS "${CMAKE_SOURCE_DIR}/DnsServer.sln")
else()
	list(APPEND DNS_SERVER_PROJECTS "${CMAKE_SOURCE_DIR}/DnsServerApp/DnsServerApp.csproj")
	file(GLOB _dns_app_projects CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/Apps/*/*.csproj")
	list(APPEND DNS_SERVER_PROJECTS ${_dns_app_projects})
endif()

set(_dns_server_commands "")
foreach(_dns_project IN LISTS DNS_SERVER_PROJECTS)
	list(APPEND _dns_server_commands
		COMMAND ${CMAKE_COMMAND} -E env DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
			${DOTNET_EXECUTABLE} build "${_dns_project}"
				--configuration ${DNS_DOTNET_CONFIGURATION}
				--verbosity minimal
	)
endforeach()

# Visual Studio builds the imported C# projects with MSBuild. Ninja (Clang)
# builds the same projects through dotnet. technitium_library runs first.
if(CMAKE_GENERATOR STREQUAL "Visual Studio 18 2026")
	function(_dns_project_key out_var absolute_path)
		cmake_path(RELATIVE_PATH absolute_path BASE_DIRECTORY "${CMAKE_SOURCE_DIR}" OUTPUT_VARIABLE _dns_rel)
		string(TOLOWER "${_dns_rel}" _dns_rel)
		string(REPLACE "/" "_" _dns_rel "${_dns_rel}")
		set(${out_var} "${_dns_rel}" PARENT_SCOPE)
	endfunction()

	set(DNS_IMPORTED_TARGETS "")
	file(STRINGS "${CMAKE_SOURCE_DIR}/DnsServer.sln" _dns_sln_lines)
	foreach(_dns_line IN LISTS _dns_sln_lines)
		string(REPLACE "\r" "" _dns_line "${_dns_line}")
		if(_dns_line MATCHES "^Project\\(\"\\{([0-9A-Fa-f-]+)\\}\"\\) = \"([^\"]+)\", \"([^\"]+)\", \"\\{([0-9A-Fa-f-]+)\\}\"")
			set(_dns_type "${CMAKE_MATCH_1}")
			set(_dns_name "${CMAKE_MATCH_2}")
			set(_dns_path "${CMAKE_MATCH_3}")
			set(_dns_guid "${CMAKE_MATCH_4}")
			if(_dns_type STREQUAL "2150E333-8FDC-42A3-9474-1A3956D46DE8")
				continue()
			endif()
			string(REPLACE "\\" "/" _dns_path "${_dns_path}")
			set(_dns_abs "${CMAKE_SOURCE_DIR}/${_dns_path}")
			include_external_msproject(${_dns_name} "${_dns_abs}"
				TYPE "{${_dns_type}}"
				GUID "{${_dns_guid}}"
				PLATFORM "Any CPU")
			set_target_properties(${_dns_name} PROPERTIES
				MAP_IMPORTED_CONFIG_DEBUG "Debug"
				MAP_IMPORTED_CONFIG_RELEASE "Release"
				MAP_IMPORTED_CONFIG_RELWITHDEBINFO "Release"
				MAP_IMPORTED_CONFIG_MINSIZEREL "Release")
			if(_dns_path MATCHES "^Apps/")
				set_target_properties(${_dns_name} PROPERTIES FOLDER "Apps")
			else()
				set_target_properties(${_dns_name} PROPERTIES FOLDER "Server")
			endif()
			_dns_project_key(_dns_key "${_dns_abs}")
			set_property(GLOBAL PROPERTY "DNS_PROJ_${_dns_key}" "${_dns_name}")
			set_property(GLOBAL PROPERTY "DNS_PROJPATH_${_dns_name}" "${_dns_abs}")
			list(APPEND DNS_IMPORTED_TARGETS "${_dns_name}")
		endif()
	endforeach()

	foreach(_dns_name IN LISTS DNS_IMPORTED_TARGETS)
		add_dependencies(${_dns_name} technitium_library)
	endforeach()

	foreach(_dns_name IN LISTS DNS_IMPORTED_TARGETS)
		get_property(_dns_location GLOBAL PROPERTY "DNS_PROJPATH_${_dns_name}")
		if(NOT _dns_location OR NOT EXISTS "${_dns_location}")
			continue()
		endif()
		cmake_path(GET _dns_location PARENT_PATH _dns_proj_dir)
		file(STRINGS "${_dns_location}" _dns_proj_lines)
		foreach(_dns_proj_line IN LISTS _dns_proj_lines)
			if(_dns_proj_line MATCHES "ProjectReference Include=\"([^\"]+)\"")
				set(_dns_ref "${CMAKE_MATCH_1}")
				string(REPLACE "\\" "/" _dns_ref "${_dns_ref}")
				cmake_path(ABSOLUTE_PATH _dns_ref BASE_DIRECTORY "${_dns_proj_dir}" NORMALIZE)
				_dns_project_key(_dns_ref_key "${_dns_ref}")
				get_property(_dns_ref_target GLOBAL PROPERTY "DNS_PROJ_${_dns_ref_key}")
				if(_dns_ref_target AND NOT _dns_ref_target STREQUAL _dns_name)
					add_dependencies(${_dns_name} ${_dns_ref_target})
				endif()
			endif()
		endforeach()
	endforeach()

	add_custom_target(dns_server ALL)
	add_dependencies(dns_server ${DNS_IMPORTED_TARGETS})
	if(TARGET DnsServerApp)
		set_property(DIRECTORY ${CMAKE_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT DnsServerApp)
	endif()
else()
	add_custom_target(dns_server ALL
		${_dns_server_commands}
		WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
		USES_TERMINAL
		VERBATIM
		COMMENT "Build Technitium DNS Server"
	)
	add_dependencies(dns_server technitium_library)
endif()

add_custom_target(publish
	COMMAND ${CMAKE_COMMAND} -E env DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
		${DOTNET_EXECUTABLE} publish "${CMAKE_SOURCE_DIR}/DnsServerApp/DnsServerApp.csproj"
			--configuration ${DNS_DOTNET_CONFIGURATION}
			--verbosity minimal
			--output "${CMAKE_BINARY_DIR}/publish/$<IF:$<CONFIG:Debug>,Debug,Release>"
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	USES_TERMINAL
	VERBATIM
	COMMENT "Publish DnsServerApp"
)
add_dependencies(publish dns_server)

# dist/DnsServerSetup.exe for vs2026, dist/DnsServerSetup_clang.exe for the clang preset.
# The portable archive and setup zip use the same suffix.
set(_dns_installer_host 0)
if(WIN32)
	set(_dns_installer_host 1)
endif()
add_custom_target(installers
	COMMAND ${CMAKE_COMMAND}
		-DSOURCE_DIR=${CMAKE_SOURCE_DIR}
		-DBINARY_DIR=${CMAKE_BINARY_DIR}
		-DDOTNET_EXECUTABLE=${DOTNET_EXECUTABLE}
		-DCONFIGURATION=$<IF:$<CONFIG:Debug>,Debug,Release>
		-DTOOLCHAIN=${DNS_TOOLCHAIN}
		-DHOST_WINDOWS=${_dns_installer_host}
		-P ${CMAKE_SOURCE_DIR}/cmake/PackageInstallers.cmake
	WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
	USES_TERMINAL
	VERBATIM
	COMMENT "Package installers into dist"
)
add_dependencies(installers publish)

message(STATUS "DNS toolchain: ${DNS_TOOLCHAIN}")
if(DNS_TOOLCHAIN STREQUAL "clang")
	message(STATUS "Clang: ${DNS_CLANG_CXX} (${_dns_clang_version})")
endif()
message(STATUS ".NET SDK host: ${DOTNET_EXECUTABLE}")
message(STATUS "TechnitiumLibrary: ${DNS_LIBRARY_ROOT} (build local master, then restore the previous branch)")
if(DNS_MSBUILD_EXECUTABLE)
	message(STATUS "MSBuild: ${DNS_MSBUILD_EXECUTABLE}")
endif()
