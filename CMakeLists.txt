cmake_minimum_required(VERSION 3.10)
project(MeshNetwork)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

add_executable(mesh_node mesh_node.cpp)

# Include OpenSSL headers
target_include_directories(mesh_node PRIVATE ${OPENSSL_INCLUDE_DIR})

# Platform-specific settings
if(WIN32)
    target_link_libraries(mesh_node ws2_32 OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(mesh_node pthread OpenSSL::SSL OpenSSL::Crypto)
endif()

# Set output directory
set_target_properties(mesh_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)