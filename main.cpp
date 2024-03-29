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
#include "ArpGui.h"
#include "messages.h"

// I know global variables are usually bad but
bool                               stopCapturing = false;
std::map<std::string, std::string> macToUsernameMapping;


//-----------------------------------------------------------------------------
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

    ArpChat::ArpChat* userData = ( ArpChat::ArpChat* ) user;

    // We got a new user
    if ( message.prefix == NEW_USER_ANNOUNCEMENT )
    {
        macToUsernameMapping[ message.mac ] = message.message;
        std::string buf = std::string( "New User (" ) + message.message +
                          ") entered the chat";

        userData->AddMessage( buf );

        return;
    }

    auto userName   = macToUsernameMapping[ message.mac ];
    message.message = userName += ": " + message.message;

    // Store the result in the queue for the UI thread.
    userData->AddMessage( message.message );
}

//-----------------------------------------------------------------------------
void capturePackets( ArpChat::ArpChat& arpChat )
{
    char errbuf[ PCAP_ERRBUF_SIZE ];

    // Open a network interface for packet capture
    pcap_t* handle =
        pcap_open_live( arpChat.getInterface(), BUFSIZ, 1, 1000, errbuf );

    if ( handle == nullptr )
    {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        printf( "Possible available network interfaces:\n" );
        ArpChat::showActiveInterfaces();
        exit( 1 );
    }

    // Set a filter to capture only ARP packets
    struct bpf_program fp;
    const char*        filter_exp = "arp";
    bpf_u_int32        mask;
    bpf_u_int32        net;

    if ( pcap_lookupnet( arpChat.getInterface(), &net, &mask, errbuf ) == -1 )
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

//-----------------------------------------------------------------------------
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

    // Calls arpGui and arpProtocol to get the userName and send it via
    // arpProtocol
    arpChat.announceNewUser( macToUsernameMapping );
    arpChat.prepareGui();

    // Start a thread for automatic updates using a timer.
    //  This is needed to automatically refresh the chat gui
    //  If not, then it only refreshes on actual change for example typing a key
    std::thread timerThread(
        [ & ]
        {
            while ( !stopCapturing )
            {
                std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
                arpChat.postGuiEvent( ftxui::Event::Custom );
            }
        } );

    arpChat.run();

    // Wait for the capture thread to finish
    captureThread.join();

    // Wait for the timer thread to finish
    timerThread.join();

    return 0;
}
