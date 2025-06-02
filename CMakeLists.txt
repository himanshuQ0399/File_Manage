cmake_minimum_required(VERSION 3.15)

project(FileManagerParallel)

# Set vcpkg toolchain
set(CMAKE_TOOLCHAIN_FILE "C:/Users/Qikfox/Documents/file_parallelism/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(httplib CONFIG REQUIRED)

# Define executable
add_executable(file_manager
    src/file_manager.cpp
    src/server.cpp
    src/main.cpp
)

# Define CPPHTTPLIB_OPENSSL_SUPPORT
target_compile_definitions(file_manager PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT=1)

# Link libraries
target_link_libraries(file_manager PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    httplib::httplib
)

# Include directories
target_include_directories(file_manager PRIVATE ${CMAKE_SOURCE_DIR}/src)