#include <libnet.h>
#include <memory>
#include <mutex>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <string>

#include "ArpChat.h"
#include "messages.h"
#include "utils.h"

namespace ArpChat
{
void ArpChat::AddMessage( const std::string& message )
{
    std::lock_guard<std::mutex> lock( chatMutex );
    chatHistory.push_back( message );
    updateFlag = true;

    // Limit the chat history to a certain number of messages.
    const size_t maxHistorySize = 10;
    while ( chatHistory.size() > maxHistorySize )
    {
        chatHistory.pop_front();
    }

    // Dummy way for debugging
    if ( message.empty() == true )
    {
        exit( 1 );
    }
}

void ArpChat::announceNewUser(
    std::map<std::string, std::string> macToUsernameMapping )
{
    using namespace ftxui;

    // The data:
    std::string first_name;

    // The basic input components:
    setInputFieldText( "Enter your username" );
    Component input_first_name = arpGui.getVInputField();
    // The component tree:
    auto component = Container::Vertical( {
        arpGui.getVInputField(),
    } );

    // Tweak how the component tree is rendered:
    auto renderer =
        Renderer( component,
                  [ & ]
                  {
                      return vbox( {
                                 hbox( text( " Username : " ),
                                       arpGui.getInputField()->Render() ),
                                 text( "Hello " + arpGui.inputBuffer ),
                             } ) |
                             border;
                  } );

    // Replace these with your actual MAC and IP addresses
    uint8_t sourceMac[]    = { 0x74, 0x8f, 0x3c, 0xb9, 0x8f, 0xf5 };
    uint8_t broadcastMac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    auto screen = ScreenInteractive::TerminalOutput();
    auto component_ =
        CatchEvent( renderer,
                    [ & ]( Event event )
                    {
                        if ( event == ftxui::Event::Return )
                        {
                            // Call your function to send
                            // messages.
                            macToUsernameMapping[ macToString( sourceMac ) ] =
                                arpGui.inputBuffer;
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
    l = libnet_init( LIBNET_LINK, interface.c_str(), errbuf );
    if ( l == nullptr )
    {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        return;
    }

    // Need to make this nicer because the string_view
    std::string customData = std::string( NEW_USER_ANNOUNCEMENT.begin(),
                                          NEW_USER_ANNOUNCEMENT.end() ) +
                             arpGui.inputBuffer;

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
        arpGui.inputBuffer.clear();
    }

    // Cleanup
    libnet_destroy( l );
}

void ArpChat::sendGratuitousArp( ftxui::ScreenInteractive& screen,
                                 bool                      announceNewUser )
{
    libnet_t* l;
    char      errbuf[ LIBNET_ERRBUF_SIZE ];

    // Initialize the library
    // TODO parse from command line the device
    l = libnet_init( LIBNET_LINK, interface.c_str(), errbuf );
    if ( l == nullptr )
    {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        return;
    }

    // Replace these with your actual MAC and IP addresses
    uint8_t sourceMac[]    = { 0x74, 0x8f, 0x3c, 0xb9, 0x8f, 0xf5 };
    uint8_t broadcastMac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    std::string customData =
        std::string( MESSAGE_PREFIX.begin(), MESSAGE_PREFIX.end() ) +
        arpGui.inputBuffer;

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
        arpGui.inputBuffer.clear();
        screen.PostEvent( ftxui::Event::Custom );
    }

    // Cleanup
    libnet_destroy( l );
}

void ArpChat::setInputFieldText( const std::string& inputText )
{
    arpGui.inputField = ftxui::Input( &arpGui.inputBuffer, inputText );
}

}   // namespace ArpChat
