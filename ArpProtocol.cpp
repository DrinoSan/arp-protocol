#include <iostream>
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

#include "ArpProtocol.h"

namespace ArpChat
{

//-----------------------------------------------------------------------------
bool ArpProtocol::sendArpMessage( const std::string& inputBuffer, const std::string& MESSAGE_TYPE_PREFIX )
{
   libnet_t* l;
   char      charbuf[ LIBNET_ERRBUF_SIZE ];

    // Initialize the library
    // TODO parse from command line the device
    l = libnet_init( LIBNET_LINK, interface.c_str(), charbuf );
    if ( l == nullptr )
    {
        std::cerr << "libnet_init() failed: " << charbuf << std::endl;
        return false;
    }

    // Replace these with your actual MAC and IP addresses
    uint8_t sourceMac[]    = { 0x74, 0x8f, 0x3c, 0xb9, 0x8f, 0xf5 };
    uint8_t broadcastMac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    std::string customData =
        std::string( MESSAGE_TYPE_PREFIX.begin(), MESSAGE_TYPE_PREFIX.end() ) +
        inputBuffer;

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
        return false;
    }

    // Build Ethernet frame
    libnet_ptag_t eth_tag = libnet_build_ethernet(
        broadcastMac, sourceMac, ETHERTYPE_ARP, nullptr, 0, l, 0 );

    if ( eth_tag == -1 )
    {
        std::cerr << "libnet_build_ethernet() failed: " << libnet_geterror( l )
                  << std::endl;
        libnet_destroy( l );
        return false;
    }

    // Write the packet to the network
    int bytes_written = libnet_write( l );
    if ( bytes_written == -1 )
    {
        std::cerr << "libnet_write() failed: " << libnet_geterror( l )
                  << std::endl;
    }

    // Cleanup
    libnet_destroy( l );
    return true;
}


};
