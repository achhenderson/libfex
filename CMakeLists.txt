cmake_minimum_required(VERSION 3.20)
project(libfex
    VERSION 0.1.0
    DESCRIPTION "Modern C++ library for the fusex kernel filesystem"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build the compile_commands.json that clangd needs.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

# Make all warnings show up so the library is hygienic to embed.
add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion
                    -Wno-unused-parameter)

# --------------------------------------------------------------- library

add_library(fex
    src/session.cpp
    src/handlers.cpp
    src/mount.cpp
    src/uring_worker.cpp
    src/notifier.cpp
    src/reply.cpp)

target_include_directories(fex
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

# Need pthreads for std::thread and liburing for the io_uring transport.
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBURING REQUIRED IMPORTED_TARGET liburing>=2.5)
target_link_libraries(fex
    PUBLIC  Threads::Threads
    PRIVATE PkgConfig::LIBURING)

set_target_properties(fex PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME fex)

# --------------------------------------------------------------- example

add_executable(fex-passthrough examples/passthrough.cpp)
target_link_libraries(fex-passthrough PRIVATE fex)

add_executable(fex-notify-test examples/notify_test.cpp)
target_link_libraries(fex-notify-test PRIVATE fex)

add_executable(fex-memfs examples/memfs.cpp)
target_link_libraries(fex-memfs PRIVATE fex)

# --------------------------------------------------------------- install

include(GNUInstallDirs)
install(TARGETS fex
    EXPORT  fexTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

install(DIRECTORY include/fex
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(TARGETS fex-passthrough fex-memfs
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
