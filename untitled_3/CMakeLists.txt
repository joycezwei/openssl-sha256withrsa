cmake_minimum_required(VERSION 3.10)
project(untitled_3)

set(CMAKE_CXX_STANDARD 11)
set(INC_DIR /home/parallels/Downloads/openssl-1.0.1u/include)
set(LINK_DIR /home/parallels/Downloads/openssl-1.0.1u/lib)

include_directories(${INC_DIR})
link_directories(${LINK_DIR})
link_libraries(ssl crypto)


add_executable(untitled_3 main.cpp common_tool.cpp common_tool.h
        Base64.cpp
        Base64.h)
target_link_libraries(untitled_3 ssl)
