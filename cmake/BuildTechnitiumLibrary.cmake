if(NOT DEFINED LIB_ROOT OR NOT DEFINED DOTNET_EXECUTABLE OR NOT DEFINED CONFIGURATION OR NOT DEFINED SNAPSHOT_DIR)
	message(FATAL_ERROR "BuildTechnitiumLibrary.cmake requires LIB_ROOT, DOTNET_EXECUTABLE, CONFIGURATION, and SNAPSHOT_DIR.")
endif()

if(NOT EXISTS "${LIB_ROOT}/TechnitiumLibrary.sln" AND NOT EXISTS "${LIB_ROOT}/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj")
	message(FATAL_ERROR
		"TechnitiumLibrary was not found at:\n  ${LIB_ROOT}\n"
		"Clone it next to this repository, or configure with -DTECHNITIUM_LIBRARY_DIR=<checkout>.")
endif()

find_program(GIT_EXECUTABLE git REQUIRED)

if(NOT MSBUILD_EXECUTABLE OR MSBUILD_EXECUTABLE MATCHES "NOTFOUND$")
	set(MSBUILD_EXECUTABLE "")
endif()

execute_process(
	COMMAND "${GIT_EXECUTABLE}" -C "${LIB_ROOT}" rev-parse --is-inside-work-tree
	RESULT_VARIABLE dns_git_rc
	OUTPUT_QUIET
	ERROR_QUIET
)
if(NOT dns_git_rc EQUAL 0)
	message(FATAL_ERROR "TechnitiumLibrary at ${LIB_ROOT} is not a git checkout, so the build cannot select master.")
endif()

execute_process(
	COMMAND "${GIT_EXECUTABLE}" -C "${LIB_ROOT}" rev-parse HEAD
	OUTPUT_VARIABLE dns_previous_commit
	OUTPUT_STRIP_TRAILING_WHITESPACE
	RESULT_VARIABLE dns_git_rc
)
if(NOT dns_git_rc EQUAL 0 OR NOT dns_previous_commit)
	message(FATAL_ERROR "Could not read the current TechnitiumLibrary commit.")
endif()

execute_process(
	COMMAND "${GIT_EXECUTABLE}" -C "${LIB_ROOT}" branch --show-current
	OUTPUT_VARIABLE dns_previous_branch
	OUTPUT_STRIP_TRAILING_WHITESPACE
	RESULT_VARIABLE dns_git_rc
)
if(NOT dns_git_rc EQUAL 0)
	message(FATAL_ERROR "Could not read the current TechnitiumLibrary branch.")
endif()

if(dns_previous_branch)
	set(dns_previous_label "${dns_previous_branch}")
	set(dns_detached FALSE)
else()
	set(dns_previous_label "detached HEAD ${dns_previous_commit}")
	set(dns_detached TRUE)
endif()

execute_process(
	COMMAND "${GIT_EXECUTABLE}" -C "${LIB_ROOT}" status --porcelain
	OUTPUT_VARIABLE dns_dirty
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(dns_dirty AND NOT dns_previous_branch STREQUAL "master")
	message(FATAL_ERROR
		"TechnitiumLibrary has uncommitted changes, so the build did not leave ${dns_previous_label}:\n${dns_dirty}\n"
		"Commit or stash those changes, then build again.")
endif()

execute_process(
	COMMAND "${GIT_EXECUTABLE}" -C "${LIB_ROOT}" show-ref --verify --quiet refs/heads/master
	RESULT_VARIABLE dns_git_rc
)
if(NOT dns_git_rc EQUAL 0)
	message(FATAL_ERROR
		"TechnitiumLibrary has no local master branch. The build uses that branch and does not fetch or pull.")
endif()

# Checkout is not reverted by a later failing command, so restore from this script.
macro(dns_restore_library_branch)
	if(dns_switched)
		# The tree was clean before leaving this commit. --force drops files the library build rewrote.
		if(dns_detached)
			execute_process(
				COMMAND "${CMAKE_COMMAND}" -E env GIT_TERMINAL_PROMPT=0
					"${GIT_EXECUTABLE}" -C "${LIB_ROOT}" checkout --force --quiet --detach "${dns_previous_commit}"
				ERROR_VARIABLE dns_restore_err
				RESULT_VARIABLE dns_restore_rc
			)
		else()
			execute_process(
				COMMAND "${CMAKE_COMMAND}" -E env GIT_TERMINAL_PROMPT=0
					"${GIT_EXECUTABLE}" -C "${LIB_ROOT}" checkout --force --quiet "${dns_previous_branch}"
				ERROR_VARIABLE dns_restore_err
				RESULT_VARIABLE dns_restore_rc
			)
		endif()
		if(NOT dns_restore_rc EQUAL 0)
			message(FATAL_ERROR
				"TechnitiumLibrary was left checked out at master. Restore ${dns_previous_label} manually.\n${dns_restore_err}")
		endif()

		if(dns_detached)
			execute_process(
				COMMAND "${GIT_EXECUTABLE}" -C "${LIB_ROOT}" rev-parse HEAD
				OUTPUT_VARIABLE dns_now
				OUTPUT_STRIP_TRAILING_WHITESPACE
			)
			if(NOT dns_now STREQUAL dns_previous_commit)
				message(FATAL_ERROR "TechnitiumLibrary is at ${dns_now} after the build. It was ${dns_previous_label}.")
			endif()
		else()
			execute_process(
				COMMAND "${GIT_EXECUTABLE}" -C "${LIB_ROOT}" branch --show-current
				OUTPUT_VARIABLE dns_now
				OUTPUT_STRIP_TRAILING_WHITESPACE
			)
			if(NOT dns_now STREQUAL dns_previous_branch)
				message(FATAL_ERROR "TechnitiumLibrary is on ${dns_now} after the build. It was ${dns_previous_label}.")
			endif()
		endif()
		message(STATUS "Restored TechnitiumLibrary to ${dns_previous_label}")
	endif()
endmacro()

set(dns_switched FALSE)
if(NOT dns_previous_branch STREQUAL "master")
	message(STATUS "Checking out TechnitiumLibrary master (leaving ${dns_previous_label})")
	execute_process(
		COMMAND "${CMAKE_COMMAND}" -E env GIT_TERMINAL_PROMPT=0
			"${GIT_EXECUTABLE}" -C "${LIB_ROOT}" checkout --quiet master
		ERROR_VARIABLE dns_git_err
		RESULT_VARIABLE dns_git_rc
	)
	if(NOT dns_git_rc EQUAL 0)
		message(FATAL_ERROR "Could not check out TechnitiumLibrary master.\n${dns_git_err}")
	endif()
	set(dns_switched TRUE)
else()
	message(STATUS "TechnitiumLibrary is already on master")
endif()

set(dns_projects
	TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj
	TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj
	TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj
)
set(dns_build_failed FALSE)
foreach(dns_rel IN LISTS dns_projects)
	if(NOT EXISTS "${LIB_ROOT}/${dns_rel}")
		continue()
	endif()
	execute_process(
		COMMAND "${CMAKE_COMMAND}" -E env DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
			"${DOTNET_EXECUTABLE}" build "${LIB_ROOT}/${dns_rel}"
				--configuration "${CONFIGURATION}"
				--verbosity minimal
		RESULT_VARIABLE dns_build_rc
	)
	if(NOT dns_build_rc EQUAL 0)
		set(dns_build_failed TRUE)
		break()
	endif()
endforeach()

if(NOT dns_build_failed AND WIN32 AND MSBUILD_EXECUTABLE)
	set(dns_firewall "${LIB_ROOT}/TechnitiumLibrary.Net.Firewall/TechnitiumLibrary.Net.Firewall.csproj")
	if(EXISTS "${dns_firewall}")
		execute_process(
			COMMAND "${MSBUILD_EXECUTABLE}" "${dns_firewall}"
				/nologo /v:m
				"/p:Configuration=${CONFIGURATION}"
				/p:AppendTargetFrameworkToOutputPath=false
				"/p:OutputPath=${LIB_ROOT}/bin/"
			RESULT_VARIABLE dns_build_rc
		)
		if(NOT dns_build_rc EQUAL 0)
			set(dns_build_failed TRUE)
		endif()
	endif()
endif()

# bin/ is gitignored, but a branch switch still drops a file that the other commit tracked.
# Keep the master assemblies outside the repo and put them back after the checkout returns.
set(dns_built_dlls "")
if(NOT dns_build_failed)
	file(GLOB dns_built_dlls "${LIB_ROOT}/bin/TechnitiumLibrary*.dll" "${LIB_ROOT}/bin/TechnitiumLibrary*.pdb")
	if(dns_built_dlls)
		file(MAKE_DIRECTORY "${SNAPSHOT_DIR}")
		file(COPY ${dns_built_dlls} DESTINATION "${SNAPSHOT_DIR}")
	endif()
endif()

dns_restore_library_branch()

if(NOT dns_build_failed AND dns_built_dlls)
	file(MAKE_DIRECTORY "${LIB_ROOT}/bin")
	file(GLOB dns_snapshot "${SNAPSHOT_DIR}/TechnitiumLibrary*.dll" "${SNAPSHOT_DIR}/TechnitiumLibrary*.pdb")
	file(COPY ${dns_snapshot} DESTINATION "${LIB_ROOT}/bin")
endif()

if(dns_build_failed)
	message(FATAL_ERROR "TechnitiumLibrary master failed to build. The checkout is ${dns_previous_label}.")
endif()
