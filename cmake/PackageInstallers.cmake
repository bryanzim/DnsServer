if(NOT DEFINED SOURCE_DIR OR NOT DEFINED BINARY_DIR OR NOT DEFINED DOTNET_EXECUTABLE OR NOT DEFINED CONFIGURATION OR NOT DEFINED TOOLCHAIN)
	message(FATAL_ERROR "PackageInstallers.cmake requires SOURCE_DIR, BINARY_DIR, DOTNET_EXECUTABLE, CONFIGURATION, and TOOLCHAIN.")
endif()

if(TOOLCHAIN STREQUAL "clang")
	set(dns_suffix "_clang")
else()
	set(dns_suffix "")
endif()

set(dns_dist "${SOURCE_DIR}/dist")
set(dns_portable_dir "${BINARY_DIR}/publish/${CONFIGURATION}")
set(dns_win_publish "${BINARY_DIR}/win-publish")
file(MAKE_DIRECTORY "${dns_dist}")

function(dns_run)
	execute_process(
		COMMAND ${ARGN}
		RESULT_VARIABLE dns_rc
	)
	if(NOT dns_rc EQUAL 0)
		message(FATAL_ERROR "Command failed (${dns_rc}): ${ARGN}")
	endif()
endfunction()

function(dns_run_in dns_workdir)
	execute_process(
		COMMAND ${ARGN}
		WORKING_DIRECTORY "${dns_workdir}"
		RESULT_VARIABLE dns_rc
	)
	if(NOT dns_rc EQUAL 0)
		message(FATAL_ERROR "Command failed (${dns_rc}) in ${dns_workdir}: ${ARGN}")
	endif()
endfunction()

if(HOST_WINDOWS)
	if(NOT EXISTS "${dns_portable_dir}/DnsServerApp.dll")
		message(FATAL_ERROR "DnsServerApp was not published to ${dns_portable_dir}.")
	endif()

	set(_dns_iscc_candidates
		"C:/Inno Setup 7/ISCC.exe"
		"C:/Program Files/Inno Setup 7/ISCC.exe"
		"C:/Program Files (x86)/Inno Setup 7/ISCC.exe"
	)
	set(dns_iscc "")
	foreach(_dns_iscc IN LISTS _dns_iscc_candidates)
		if(EXISTS "${_dns_iscc}")
			set(dns_iscc "${_dns_iscc}")
			break()
		endif()
	endforeach()
	if(NOT dns_iscc)
		message(FATAL_ERROR "Inno Setup 7 compiler (ISCC.exe) was not found.")
	endif()

	file(REMOVE_RECURSE "${dns_win_publish}")
	file(MAKE_DIRECTORY "${dns_win_publish}")
	file(TO_CMAKE_PATH "${dns_win_publish}" dns_win_publish)

	dns_run(${CMAKE_COMMAND} -E env DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
		"${DOTNET_EXECUTABLE}" publish "${SOURCE_DIR}/DnsServerWindowsService/DnsServerWindowsService.csproj"
			--configuration ${CONFIGURATION}
			-p:PublishProfile=FolderProfile
			-p:PublishDir=${dns_win_publish}/
			--verbosity minimal)
	dns_run(${CMAKE_COMMAND} -E env DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
		"${DOTNET_EXECUTABLE}" publish "${SOURCE_DIR}/DnsServerSystemTrayApp/DnsServerSystemTrayApp.csproj"
			--configuration ${CONFIGURATION}
			--framework net11.0-windows7.0
			-p:PublishDir=${dns_win_publish}/
			--verbosity minimal)

	if(NOT EXISTS "${dns_win_publish}/DnsServerSystemTrayApp.exe" OR NOT EXISTS "${dns_win_publish}/DnsService.exe")
		message(FATAL_ERROR "Windows publish did not produce the tray app and service in ${dns_win_publish}.")
	endif()

	set(dns_setup_base "DnsServerSetup${dns_suffix}")
	dns_run("${dns_iscc}"
		"/DSetupBaseName=${dns_setup_base}"
		"/DPublishDir=${dns_win_publish}"
		"${SOURCE_DIR}/DnsServerWindowsSetup/DnsServerSetup.iss")

	set(dns_setup "${dns_dist}/${dns_setup_base}.exe")
	if(NOT EXISTS "${dns_setup}")
		message(FATAL_ERROR "Inno Setup did not write ${dns_setup}.")
	endif()

	set(dns_setup_zip "${dns_dist}/${dns_setup_base}.zip")
	file(REMOVE "${dns_setup_zip}")
	dns_run_in("${dns_dist}" ${CMAKE_COMMAND} -E tar cf "${dns_setup_zip}" --format=zip "${dns_setup_base}.exe")
	message(STATUS "Setup: ${dns_setup}")
	message(STATUS "Setup zip: ${dns_setup_zip}")
endif()

set(dns_portable "${dns_dist}/DnsServerPortable${dns_suffix}.tar.gz")
if(NOT EXISTS "${dns_portable_dir}/DnsServerApp.dll")
	message(FATAL_ERROR "DnsServerApp was not published to ${dns_portable_dir}.")
endif()
file(REMOVE "${dns_portable}")
dns_run_in("${dns_portable_dir}" ${CMAKE_COMMAND} -E tar czf "${dns_portable}" .)
message(STATUS "Portable: ${dns_portable}")
