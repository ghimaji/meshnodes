cmake_minimum_required(VERSION 3.10)
project(MeshNetwork)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(mesh_node mesh_node.cpp)

# Platform-specific settings
if(WIN32)
    target_link_libraries(mesh_node ws2_32)
else()
    target_link_libraries(mesh_node pthread)
endif()

# Set output directory
set_target_properties(mesh_node PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)