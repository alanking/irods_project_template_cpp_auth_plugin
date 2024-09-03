cmake_minimum_required(VERSION 3.7.0 FATAL_ERROR)

set(IRODS_MINIMUM_VERSION "4.3.3")
find_package(IRODS "${IRODS_MINIMUM_VERSION}" REQUIRED)
set(IRODS_PLUGIN_VERSION "0.1.0")

set(IRODS_PACKAGE_REVISION "0")

include(IrodsCXXCompiler)
set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})

set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")

project(irods_project_template_cpp_auth_plugin
	VERSION "${IRODS_PLUGIN_VERSION}"
	LANGUAGES CXX
)

# Include this module to inherit iRODS's defaults for RPATH/RUNPATH handling
include(IrodsRunpathDefaults)

# The plugin_target_part will come into play when building separate client and server plugins.
set(plugin_target_part "irods_auth_plugin-project_template_cpp")
string(REPLACE "_" "-" project_component_part "${plugin_target_part}")

include("${IRODS_TARGETS_PATH}")

include(GNUInstallDirs)
include(UseLibCXX)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(nlohmann_json "3.6.1" REQUIRED)

find_package(fmt "8.1.1"
	HINTS "${IRODS_EXTERNALS_FULLPATH_FMT}")
find_package(spdlog "1.9.2"
	HINTS "${IRODS_EXTERNALS_FULLPATH_SPDLOG}")

if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build {Debug, Release}." FORCE)
	message(STATUS "Setting unspecified CMAKE_BUILD_TYPE to '${CMAKE_BUILD_TYPE}'")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fpermissive>)
endif()

set(IRODS_BUILD_WITH_WERROR OFF CACHE BOOL "Choose whether to compile with -Werror.")

if (IRODS_BUILD_WITH_WERROR)
  add_compile_options(-Werror)
endif()

add_subdirectory(plugin)

# Install the test file(s) alongside the server package.
install(
	FILES
	${CMAKE_SOURCE_DIR}/packaging/test_project_template_cpp_auth_plugin.py
	DESTINATION ${IRODS_HOME_DIRECTORY}/scripts/irods/test
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
	COMPONENT
	"${project_component_part}-server"
)

set(PLUGIN_PACKAGE_NAME "irods-auth-plugin-nop")

include(IrodsCPackCommon)

list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_PLUGINS_DIRECTORY}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_PLUGINS_DIRECTORY}/auth")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods")
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "${CPACK_PACKAGING_INSTALL_PREFIX}${IRODS_HOME_DIRECTORY}/scripts/irods/test")

set(CPACK_PACKAGE_VERSION ${IRODS_PLUGIN_VERSION})
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")

set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_SOURCE_DIR}/packaging/postinst;")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE "${CMAKE_SOURCE_DIR}/packaging/postinst")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

string(TOUPPER "${project_component_part}-client" irods_plugin_package_client_component)
string(TOUPPER "${project_component_part}-server" irods_plugin_package_server_component)

set(CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_NAME "${PLUGIN_PACKAGE_NAME}-client")
set(CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_DEPENDS "irods-runtime (= ${IRODS_VERSION}), libc6")
set(CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_BREAKS "${PLUGIN_PACKAGE_NAME} (<< 4.90.0.0-1~)")
set(CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_REPLACES "${PLUGIN_PACKAGE_NAME} (<< 4.90.0.0-1~)")

set(CPACK_RPM_${irods_plugin_package_client_component}_PACKAGE_NAME "${PLUGIN_PACKAGE_NAME}-client")
set(CPACK_RPM_${irods_plugin_package_client_component}_PACKAGE_REQUIRES "irods-runtime = ${IRODS_VERSION}")

set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_NAME "${PLUGIN_PACKAGE_NAME}-server")
set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_DEPENDS "irods-server (= ${IRODS_VERSION}), ${CPACK_DEBIAN_${irods_plugin_package_client_component}_PACKAGE_NAME} (= ${CPACK_PACKAGE_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE})")
set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_BREAKS "${PLUGIN_PACKAGE_NAME} (<< 4.90.0.0-1~)")
set(CPACK_DEBIAN_${irods_plugin_package_server_component}_PACKAGE_REPLACES "${PLUGIN_PACKAGE_NAME} (<< 4.90.0.0-1~)")

set(CPACK_RPM_${irods_plugin_package_server_component}_PACKAGE_NAME "${PLUGIN_PACKAGE_NAME}-server")
set(CPACK_RPM_${irods_plugin_package_server_component}_PACKAGE_REQUIRES "irods-server = ${IRODS_VERSION}, ${CPACK_RPM_${irods_plugin_package_client_component}_PACKAGE_NAME} = ${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}")

if (NOT CPACK_GENERATOR)
	set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
	message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)
