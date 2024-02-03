#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <libnet.h>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <queue>
#include <string>
#include <thread>

// ArpChat includes
#include "ArpChat.h"
#include "gui.h"
#include "messages.h"
#include "utils.h"

// I know global variables are usually bad but
std::mutex              capturedResultMutex;
std::queue<std::string> capturedResults;
bool                    stopCapturing = false;

// Persistent input buffer.
std::string inputBuffer;

std::map<std::string, std::string> macToUsernameMapping;

void packetHandler( unsigned char* user, const struct pcap_pkthdr* pkthdr,
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

    ArpChat::ArpMessage message;
    message.parseArpChatMessage( packet );

    std::lock_guard<std::mutex> lock( capturedResultMutex );
    // We got a new user
    if ( message.prefix == NEW_USER_ANNOUNCEMENT )
    {
        macToUsernameMapping[ message.mac ] = message.message;
        std::string buf = std::string( "New User (" ) + message.message +
                          ") entered the chat";
	ArpChat::ArpChat* userData = ( ArpChat::ArpChat* ) user;

	userData->AddMessage(buf);
        capturedResults.push( message.message );

        return;
    }

    auto userName   = macToUsernameMapping[ message.mac ];
    message.message = userName += ": " + message.message;

    // Store the result in the queue for the UI thread.
    capturedResults.push( message.message );
    ArpChat::ArpChat* userData = ( ArpChat::ArpChat* ) user;
    userData->AddMessage( message.message );
}

void capturePackets( ArpChat::ArpChat& arpChat )
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

    // Start capturing packets and pass them to the packetHandler function
    pcap_loop( handle, 0, packetHandler, ( u_char* ) &arpChat );


    pcap_close( handle );
}

void sendGratuitousArp( ftxui::ScreenInteractive& screen,
                        ArpChat::ArpChat&         arpChat,
                        bool                      announceNewUser = false )
{
    libnet_t* l;
    char      errbuf[ LIBNET_ERRBUF_SIZE ];

    // Initialize the library
    // TODO parse from command line the device
    l = libnet_init( LIBNET_LINK, "en0", errbuf );
    if ( l == nullptr )
    {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        return;
    }

    // Replace these with your actual MAC and IP addresses
    uint8_t sourceMac[]    = { 0x74, 0x8f, 0x3c, 0xb9, 0x8f, 0xf5 };
    uint8_t broadcastMac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    std::string customData = MESSAGE_PREFIX + arpChat.arpGui.inputBuffer;

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
        // Clear the input field and trigger a custom event to update the UI
        arpChat.arpGui.inputBuffer.clear();
        screen.PostEvent( ftxui::Event::Custom );
    }

    // Cleanup
    libnet_destroy( l );
}

// This function needs a refactoring because copy paste from above
void announceNewUser()
{
    ////////////////////////////////////////////////////////////
    //////////////////////// GUI BEGIN /////////////////////////
    ////////////////////////////////////////////////////////////

    using namespace ftxui;

    // The data:
    std::string first_name;

    // The basic input components:
    Component input_first_name = Input( &first_name, "Enter your username" );
    // The component tree:
    auto component = Container::Vertical( {
        input_first_name,
    } );

    // Tweak how the component tree is rendered:
    auto renderer = Renderer( component,
                              [ & ]
                              {
                                  return vbox( {
                                             hbox( text( " Username : " ),
                                                   input_first_name->Render() ),
                                             text( "Hello " + first_name ),
                                         } ) |
                                         border;
                              } );

    // Replace these with your actual MAC and IP addresses
    uint8_t sourceMac[]    = { 0x74, 0x8f, 0x3c, 0xb9, 0x8f, 0xf5 };
    uint8_t broadcastMac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    auto screen     = ScreenInteractive::TerminalOutput();
    auto component_ = CatchEvent(
        renderer,
        [ & ]( Event event )
        {
            if ( event == ftxui::Event::Return )
            {
                // Call your function to send
                // messages.
                macToUsernameMapping[ ArpChat::macToString( sourceMac ) ] =
                    first_name;
                screen.ExitLoopClosure()();
                return true;
            }
            return false;
        } );

    screen.Loop( component_ );

    ////////////////////////////////////////////////////////////
    //////////////////////// GUI END ///////////////////////////
    ////////////////////////////////////////////////////////////

    libnet_t* l;
    char      errbuf[ LIBNET_ERRBUF_SIZE ];

    // Initialize the library
    // TODO parse from command line the device
    l = libnet_init( LIBNET_LINK, "en0", errbuf );
    if ( l == nullptr )
    {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        return;
    }

    std::string customData = NEW_USER_ANNOUNCEMENT + first_name;

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
        // Clear the input field and trigger a custom event to update the UI
        inputBuffer.clear();
    }

    // Cleanup
    libnet_destroy( l );
}

int main()
{
    // Start a thread for packet capture
    auto        arpChat = ArpChat::ArpChat();
    std::thread captureThread( [ &arpChat ]() { capturePackets( arpChat ); } );

    announceNewUser();

    ////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////// GUI STUFF BEGINN
    /////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////

    // Main UI loop.
    using namespace ftxui;
    auto screen = ScreenInteractive::TerminalOutput();

    auto renderer = Renderer(
        arpChat.arpGui.getVInputField(),
        [ & ]
        {
            std::lock_guard<std::mutex> lock( arpChat.chatMutex );

            std::vector<Element> chatElements;
            for ( const auto& message : arpChat.chatHistory )
            {
                chatElements.push_back( text( message ) );
            }

            // Combine the text elements into a vbox.
            auto tmpVbox = vbox( std::move( chatElements ) );

            // Reset the update flag.
            arpChat.updateFlag = false;

            // Create a vbox for the chat history and input field.
            auto vboxWithInput =
                vbox( { text( L"Chat History" ) | hcenter, tmpVbox, separator(),
                        hbox( text( " Message Input : " ),
                              arpChat.arpGui.getInputField()->Render() ) } ) |
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
                            sendGratuitousArp( screen, arpChat );
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
    // timerThread.join();

    return 0;
}
