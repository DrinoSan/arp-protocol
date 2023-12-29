#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <libnet.h>
#include <memory>   // for allocator, __shared_ptr_access
#include <mutex>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <string>   // for char_traits, operator+, string, basic_string
#include <thread>

// FTXUI stuff
#include "ftxui/component/component.hpp"
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/string.hpp>

// ArpChat includes
#include "messages.h"

void AddMessage( const std::string& message );

std::mutex              capturedResultMutex;
std::queue<std::string> capturedResults;
bool                    stopCapturing = false;

// Chat and history stuff
std::mutex              chatMutex;
std::deque<std::string> chatHistory;

// Persistent input buffer.
std::string inputBuffer;
// Persistent input field.
ftxui::Component inputField =
    ftxui::Input( &inputBuffer, "Type a message and press Enter..." );

bool updateFlag = false;

void print_mac_address( const unsigned char* mac_address )
{
    for ( int i = 0; i < 6; ++i )
    {
        printf( "%02X", mac_address[ i ] );
        if ( i < 5 )
            std::cout << ":";
    }
}

void print_packet( const unsigned char* packet, int length )
{
    for ( int i = 0; i < length; ++i )
    {
        // setw: https://en.cppreference.com/w/cpp/io/manip/setw
        // setfill: https://en.cppreference.com/w/cpp/io/manip/setfill
        std::cout << std::hex << std::setw( 2 ) << std::setfill( '0' )
                  << static_cast<int>( packet[ i ] ) << " ";
        if ( ( i + 1 ) % 16 == 0 )
        {
            std::cout << std::endl;
        }
    }
    std::cout << std::dec << std::endl;
}

void packet_handler( unsigned char* user, const struct pcap_pkthdr* pkthdr,
                     const unsigned char* packet )
{
    // print_packet( packet, pkthdr->len );
    if ( !ArpChat::EthernetFrame::isArp( packet ) ||
         !ArpChat::ArpMessage::isArpChatMessage( packet ) )
    {
        // We are only interested in arp packages
        return;
    }

    ArpChat::EthernetFrame frame( packet, pkthdr->caplen );

    std::cout << "\n";

    std::cout << "-------------+++++++++++++" << std::endl;
    ArpChat::ArpMessage message;
    message.parseArpChatMessage( packet );
    // Store the result in the queue for the UI thread.
    std::lock_guard<std::mutex> lock( capturedResultMutex );
    capturedResults.push( message.message );
    std::cout << "MESSAGE: " << message.message << std::endl;
    AddMessage( message.message );

    std::cout << "+++++++++++++-------------" << std::endl;
}

void capturePackets()
{
    char errbuf[ PCAP_ERRBUF_SIZE ];

    // Open a network interface for packet capture
    pcap_t* handle = pcap_open_live( "en0", BUFSIZ, 1, 1000, errbuf );

    if ( handle == nullptr )
    {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return;
    }

    // Set a filter to capture only ARP packets
    struct bpf_program fp;
    const char*        filter_exp = "arp";
    bpf_u_int32        mask;
    bpf_u_int32        net;

    if ( pcap_lookupnet( "en0", &net, &mask, errbuf ) == -1 )
    {
        std::cerr << "Couldn't get netmask for device: " << errbuf << std::endl;
        net  = 0;
        mask = 0;
    }

    // Check: https://en.wikipedia.org/wiki/Berkeley_Packet_Filter
    if ( pcap_compile( handle, &fp, filter_exp, 0, net ) == -1 )
    {
        std::cerr << "Couldn't parse filter " << filter_exp << ": "
                  << pcap_geterr( handle ) << std::endl;
        return;
    }

    if ( pcap_setfilter( handle, &fp ) == -1 )
    {
        std::cerr << "Couldn't install filter " << filter_exp << ": "
                  << pcap_geterr( handle ) << std::endl;
        return;
    }

    // Start capturing packets and pass them to the packet_handler function
    pcap_loop( handle, 0, packet_handler, nullptr );

    pcap_close( handle );
}

void sendGratuitousArp( ftxui::ScreenInteractive& screen,
                        ftxui::Component&         inputField )
{
    libnet_t* l;
    char      errbuf[ LIBNET_ERRBUF_SIZE ];

    // Initialize the library
    l = libnet_init( LIBNET_LINK, "en0", errbuf );
    if ( l == nullptr )
    {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        return;
    }

    // Replace these with your actual MAC and IP addresses
    uint8_t sourceMac[]    = { 0x74, 0x8f, 0x3c, 0xb9, 0x8f, 0xf5 };
    uint8_t sourceIp[]     = { 192, 168, 0, 99 };
    uint8_t broadcastMac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    std::string customData = inputBuffer;   // Access inputBuffer here
    customData             = "SAND" + inputBuffer;

    // Build ARP packet
    libnet_ptag_t arp_tag = libnet_build_arp(
        ARPHRD_ETHER, ETHERTYPE_IP, 6, customData.size(), ARPOP_REQUEST,
        sourceMac, reinterpret_cast<uint8_t*>( customData.data() ),
        broadcastMac, reinterpret_cast<uint8_t*>( customData.data() ), nullptr,
        0, l, 0 );

    if ( arp_tag == -1 )
    {
        std::cerr << "libnet_build_arp() failed: " << libnet_geterror( l )
                  << std::endl;
        libnet_destroy( l );
        return;
    }

    // Build Ethernet frame
    libnet_ptag_t eth_tag = libnet_build_ethernet(
        broadcastMac, sourceMac, ETHERTYPE_ARP, nullptr, 0, l, 0 );

    if ( eth_tag == -1 )
    {
        std::cerr << "libnet_build_ethernet() failed: " << libnet_geterror( l )
                  << std::endl;
        libnet_destroy( l );
        return;
    }

    // Write the packet to the network
    int bytes_written = libnet_write( l );
    if ( bytes_written == -1 )
    {
        std::cerr << "libnet_write() failed: " << libnet_geterror( l )
                  << std::endl;
    }
    else
    {
        std::cout << "Gratuitous ARP packet sent successfully." << std::endl;
        // Clear the input field and trigger a custom event to update the UI
        inputBuffer.clear();
        screen.PostEvent( ftxui::Event::Custom );
    }

    // Cleanup
    libnet_destroy( l );
}

// Function to add a new message to the chat history.
void AddMessage( const std::string& message )
{
    std::lock_guard<std::mutex> lock( chatMutex );
    std::cout << "WE ADD THIS MESSAGE: " << message << '\n';
    chatHistory.push_back( message );
    updateFlag = true;

    // Limit the chat history to a certain number of messages.
    const size_t maxHistorySize = 10;
    while ( chatHistory.size() > maxHistorySize )
    {
        chatHistory.pop_front();
    }
}

void UpdateLoop()
{
    while ( true )
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );

        // Set the update flag.
        updateFlag = true;
    }
}

void TimerFunction( ftxui::ScreenInteractive& screen )
{
    while ( !stopCapturing )
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
        screen.PostEvent( ftxui::Event::Custom );
    }
}

int main()
{
    // Start a thread for packet capture
    std::thread captureThread( capturePackets );

    ////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////// GUI STUFF BEGINN
    /////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////

    // Main UI loop.
    using namespace ftxui;
    auto screen = ScreenInteractive::TerminalOutput();

    // The component tree:
    auto inputComponent = Container::Vertical( {
        inputField,
    } );

    auto renderer = Renderer(
        inputComponent,
        [ & ]
        {
            std::lock_guard<std::mutex> lock( chatMutex );

            std::vector<Element> chatElements;
            for ( const auto& message : chatHistory )
            {
                chatElements.push_back( text( message ) );
            }

            // Combine the text elements into a vbox.
            auto tmpVbox = vbox( std::move( chatElements ) );

            // Reset the update flag.
            updateFlag = false;

            // Create a vbox for the chat history and input field.
            auto vboxWithInput =
                vbox( { text( L"Chat History" ) | hcenter, tmpVbox, separator(),
                        hbox( text( " Message Input : " ),
                              inputField->Render() ) } ) |
                border;

            return vboxWithInput;
        } );

    auto component =
        CatchEvent( renderer,
                    [ & ]( Event event )
                    {
                        if ( event == ftxui::Event::Character( 'q' ) )
                        {
                            screen.ExitLoopClosure()();
                            stopCapturing = true;
                            return true;
                        }
                        else if ( event == ftxui::Event::Return )
                        {
                            // Call your function to send messages.
                            sendGratuitousArp( screen, inputField );
                            return true;
                        }
                        return false;
                    } );

    // Start a thread for automatic updates using a timer.
    std::thread timerThread(
        [ & ]
        {
            while ( !stopCapturing )
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
                screen.PostEvent( ftxui::Event::Custom );
            }
        } );

    screen.Loop( component );

    ////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////// GUI STUFF END
    ////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////

    // Wait for the capture thread to finish
    captureThread.join();

    // Wait for the timer thread to finish
    timerThread.join();

    return 0;
}
