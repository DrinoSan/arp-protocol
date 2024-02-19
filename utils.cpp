#include "utils.h"

#include <iomanip>
#include <iostream>
#include <ifaddrs.h>

namespace ArpChat
{
//-----------------------------------------------------------------------------
void print_mac_address( const unsigned char* mac_address )
{
    for ( int i = 0; i < 6; ++i ) {
        printf( "%02X", mac_address[ i ] );
        if ( i < 5 )
            std::cout << ":";
    }
}

//-----------------------------------------------------------------------------
std::string macToString( uint8_t* mac )
{
    std::string tmpMac;
    for ( int i = 0; i < 6; ++i )
    {
        tmpMac += mac[ i ];
        if ( i < 5 )
            tmpMac += ":";
    }

    return tmpMac;
}

//-----------------------------------------------------------------------------
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

//-----------------------------------------------------------------------------
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
}   // namespace ArpChat
