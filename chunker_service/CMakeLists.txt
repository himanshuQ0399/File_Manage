cmake_minimum_required(VERSION 3.15)
project(ChunkerService)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_TOOLCHAIN_FILE "C:/Users/Qikfox/Documents/file_parallelism/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(httplib CONFIG REQUIRED)
add_executable(chunker_service
    src/chunker.cpp
    src/server.cpp
    src/main.cpp
)
target_compile_definitions(chunker_service PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT=1)
target_link_libraries(chunker_service PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    httplib::httplib
)
target_include_directories(chunker_service PRIVATE ${CMAKE_SOURCE_DIR}/src)