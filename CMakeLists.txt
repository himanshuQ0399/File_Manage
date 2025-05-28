cmake_minimum_required(VERSION 3.10)
project(FileManagerParallel)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(httplib CONFIG REQUIRED)
include_directories(${CMAKE_SOURCE_DIR}/src)
add_executable(file_manager
    src/file_manager.cpp
    src/server.cpp
    src/main.cpp
)
target_link_libraries(file_manager PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    httplib::httplib
)