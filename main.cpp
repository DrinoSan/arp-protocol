#include <ifaddrs.h>
#include <iostream>
#include <libnet.h>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <string>
#include <thread>

// ArpChat includes
#include "ArpChat.h"
#include "gui.h"
#include "messages.h"

// I know global variables are usually bad but
bool                               stopCapturing = false;
std::map<std::string, std::string> macToUsernameMapping;

void showActiveInterfaces()
{
    struct ifaddrs* ifAddrStruct = nullptr;
    struct ifaddrs* ifa          = nullptr;

    if ( getifaddrs( &ifAddrStruct ) == 0 )
    {
        for ( ifa = ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next )
        {
            if ( ifa->ifa_addr != nullptr )
            {
                std::cout << "Interface: " << ifa->ifa_name << std::endl;
            }
        }

        freeifaddrs( ifAddrStruct );
    }
}

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

    // We got a new user
    if ( message.prefix == NEW_USER_ANNOUNCEMENT )
    {
        macToUsernameMapping[ message.mac ] = message.message;
        std::string buf = std::string( "New User (" ) + message.message +
                          ") entered the chat";
        ArpChat::ArpChat* userData = ( ArpChat::ArpChat* ) user;

        userData->AddMessage( buf );

        return;
    }

    auto userName   = macToUsernameMapping[ message.mac ];
    message.message = userName += ": " + message.message;

    // Store the result in the queue for the UI thread.
    ArpChat::ArpChat* userData = ( ArpChat::ArpChat* ) user;
    userData->AddMessage( message.message );
}

void capturePackets( ArpChat::ArpChat& arpChat )
{
    char errbuf[ PCAP_ERRBUF_SIZE ];

    // Open a network interface for packet capture
    pcap_t* handle =
        pcap_open_live( arpChat.interface.c_str(), BUFSIZ, 1, 1000, errbuf );

    if ( handle == nullptr )
    {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        printf("Possible available network interfaces:\n");
        showActiveInterfaces();
        exit(1);
    }

    // Set a filter to capture only ARP packets
    struct bpf_program fp;
    const char*        filter_exp = "arp";
    bpf_u_int32        mask;
    bpf_u_int32        net;

    if ( pcap_lookupnet( arpChat.interface.c_str(), &net, &mask, errbuf ) ==
         -1 )
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

int main( int argc, char* argv[] )
{
    // Parsing the bad boys
    if ( argc != 3 )
    {
        // Something is wrong
        printf( "Please provide a network interface\n" );
        printf( "\t\t Example: ./main -i en0\n" );
        printf( "\t\t Example: ./main -interface en0\n" );
        return 0;
    }

    std::string interface_flag = argv[ 1 ];
    if ( interface_flag != "-i" && interface_flag != "-interface" )
    {
        printf( "Currently only -i or -interface is supported\n" );
        return 0;
    }

    // Start a thread for packet capture
    auto        arpChat = ArpChat::ArpChat( argv[ 2 ] );
    std::thread captureThread( [ &arpChat ]() { capturePackets( arpChat ); } );

    arpChat.announceNewUser( macToUsernameMapping );

    arpChat.arpGui.prepareInputFieldForChat();

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
                            stopCapturing = false;
                            return true;
                        }
                        else if ( event == ftxui::Event::Return )
                        {
                            // Call your function to send messages.
                            arpChat.sendGratuitousArp( screen );
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
