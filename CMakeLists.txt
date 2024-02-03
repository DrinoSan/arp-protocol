cmake_minimum_required(VERSION 3.12)

project(ArpChat)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_COMPILER clang++)


# Create the executable target
add_executable(main main.cpp messages.cpp utils.cpp gui.cpp ArpChat.cpp)

# Find the ftxui package
find_package(ftxui REQUIRED)
find_package(Threads REQUIRED)

# Link against the ftxui libraries
target_link_libraries(main PRIVATE
    ftxui::screen
    ftxui::dom
    ftxui::component
    Threads::Threads
)

# Link against libpcap and libnet (adjust library name accordingly)
target_link_libraries(main PRIVATE
    pcap
    ${CMAKE_DL_LIBS}  # Link against dynamic linker library
    /opt/homebrew/Cellar/libnet/1.3/lib/libnet.a  # Adjust the path and name accordingly
)

# Include the ftxui directories for better Intellisense support
target_include_directories(main PRIVATE
    ${FTXUI_INCLUDE_DIRS}
)
