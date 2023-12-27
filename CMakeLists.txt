cmake_minimum_required(VERSION 3.12)

project(ArpChat)

set(CMAKE_CXX_STANDARD 17)

# Create the executable target
add_executable(main main.cpp messages.cpp)

# Find the ftxui package
find_package(ftxui REQUIRED)

# Link against the ftxui libraries
target_link_libraries(main PRIVATE
    ftxui::screen
    ftxui::dom
    ftxui::component
)

# Link against libpcap and libnet (adjust library name accordingly)
target_link_libraries(main PRIVATE
    pcap
    ${CMAKE_DL_LIBS}  # Link against dynamic linker library
    /opt/homebrew/Cellar/libnet/1.3/lib/libnet.a  # Adjust the path and name accordingly
)