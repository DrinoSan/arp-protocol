#include <iostream>
#include <sstream>

#include "messages.h"

namespace ArpChat
{

EthernetFrame::EthernetFrame( const unsigned char* packet, int length )
{
    destinationMacAddr = hexToString( packet );
    // Source mac addressof ethernet frame starts at offset 7
    sourceMacAddr = hexToString( packet + 6 );

    // This should be 0x0806, we check it in isArp already function
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
    std::string spaPrefix{ packetPayload + 14, packetPayload + 20 };

    // Begin of TPA prefix
    // packetPaload -> Where the payload of the ethernet starts
    // 14 -> offet till SPA
    // arpMessageLen -> length of the message max 255 (PLEN is unsigned char)
    // 6 -> Length of Target Hardware Address (THA)
    // END of TPA prefix
    // packetPayload + 14 + arpMessageLen + 6 same as above
    // 6 Lengh of prefix 1_SAND or 2_SAND
    std::string tpaPrefix{ packetPayload + 14 + arpMessageLen + 6,
                           packetPayload + 14 + arpMessageLen + 6 + 6 };

    // Check for normal message
    if ( ( spaPrefix != MESSAGE_PREFIX || tpaPrefix != MESSAGE_PREFIX ) &&
         ( spaPrefix != NEW_USER_ANNOUNCEMENT ||
           tpaPrefix != NEW_USER_ANNOUNCEMENT ) )
    {
        return false;
    }

    return true;
}

void ArpMessage::parseArpChatMessage( const unsigned char* packet )
{
    // packetPayload + 14 -> offset of the ethernetframe payload
    auto        packetPayload = packet + 14;
    std::string spaPrefix{ packetPayload + 14, packetPayload + 20 };

    auto arpMessageLen = packetPayload[ 5 ];

    // packetPayload + 14 -> Sender protocol address (SPA) beginning
    // MESSAGE_PREFIX_LENGTH -> The length of the prefix
    // Same as above
    // arpMessageLen -> Length of the user message
    std::string tmpMessage{ packetPayload + 14 + MESSAGE_PREFIX_LENGTH,
                            packetPayload + 14 + arpMessageLen };

    EthernetFrame etherFrame( packet, 0xDEADBEEF );

    prefix  = spaPrefix;
    message = tmpMessage;
    mac     = etherFrame.payload.sha;
}

}   // namespace ArpChat
