#include <iostream>
#include <sstream>

#include "messages.h"

#define MESSAGE_PREFIX "SAND"

namespace ArpChat
{

EthernetFrame::EthernetFrame( const unsigned char* packet, int length )
{
    destinationMacAddr = hexToString( packet );
    // Source mac addressof ethernet frame starts at offset 7
    sourceMacAddr = hexToString( packet + 6 );

    // This should be 0x0806, we check it in isArp already
    etherType = packet[ 12 ] << 8 | packet[ 13 ];

    auto packetPayload = packet + 14;
    payload.htype      = packetPayload[ 0 ] << 8 | packetPayload[ 1 ];
    payload.ptype      = packetPayload[ 2 ] << 8 | packetPayload[ 3 ];

    payload.hlen = packetPayload[ 4 ];
    payload.plen = packetPayload[ 5 ];

    payload.oper = packetPayload[ 6 ] << 8 | packetPayload[ 7 ];

    payload.sha = hexToString( packetPayload + 8 );
    payload.tha = hexToString( packetPayload + 18 );
}

std::string EthernetFrame::hexToString( const unsigned char* packet )
{
    std::stringstream macAddress;
    for ( int32_t i = 0; i < 6; ++i )
    {
        macAddress << std::setw( 2 ) << std::setfill( '0' ) << std::hex
                   << static_cast<int>( packet[ i ] );
        if ( i < 5 )
            macAddress << ":";
    }

    return macAddress.str();
}

std::string EthernetFrame::ipToString( const unsigned char* packet )
{
    std::stringstream ipAddress;
    for ( int32_t i = 0; i < 4; ++i )
    {
        ipAddress << static_cast<int>( packet[ i ] );
        if ( i < 3 )
            ipAddress << ".";
    }

    return ipAddress.str();
}

bool EthernetFrame::isArp( const unsigned char* packet )
{
    auto etherType = packet[ 12 ] << 8 | packet[ 13 ];

    if ( etherType == 0x0806 )
    {
        return true;
    }

    return false;
}

// -----------------------------------------------------------------------------
// ARP Message Definitions

ArpMessage::ArpMessage() {}

bool ArpMessage::isArpChatMessage( const unsigned char* packet )
{
    auto packetPayload = packet + 14;
    auto arpMessageLen = static_cast<int>( packetPayload[ 5 ] );

    // TODO make this more clear
    std::string spaPrefix{ packetPayload + 14, packetPayload + 18 };
    std::string tpaPrefix{ packetPayload + 14 + arpMessageLen + 6,
                           packetPayload + 14 + arpMessageLen + 6 + 4 };

    if ( spaPrefix != MESSAGE_PREFIX || tpaPrefix != MESSAGE_PREFIX )
    {
        return false;
    }

    return true;
}

void ArpMessage::parseArpChatMessage( const unsigned char* packet )
{
    auto        packetPayload = packet + 14;
    std::string spaPrefix{ packetPayload + 14, packetPayload + 18 };

    auto arpMessageLen = packetPayload[ 5 ];

    // This is actually not needed really
    EthernetFrame frame( packet, 0 );

    std::string tmpMessage{ packetPayload + 14,
                         packetPayload + 14 + arpMessageLen };

    prefix            = spaPrefix;
    frame.payload.spa = message;
    frame.payload.tpa = message;

    std::cout << "IS ARP CHAT MESSAGE PREFIX: " << spaPrefix << std::endl;
    std::cout << "IS ARP CHAT MESSAGE: " << tmpMessage << std::endl;

    message = tmpMessage;
}

}   // namespace ArpChat
