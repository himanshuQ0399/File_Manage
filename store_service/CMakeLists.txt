cmake_minimum_required(VERSION 3.15)
project(StoreService)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_TOOLCHAIN_FILE "C:/Users/Qikfox/Documents/file_parallelism/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(httplib CONFIG REQUIRED)
find_package(SQLite3 REQUIRED)
add_executable(store_service
    src/store.cpp
    src/server.cpp
    src/main.cpp
)
target_compile_definitions(store_service PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT=1)
target_link_libraries(store_service PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    httplib::httplib
    SQLite::SQLite3
)
target_include_directories(store_service PRIVATE ${CMAKE_SOURCE_DIR}/src)