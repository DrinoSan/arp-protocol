#pragma once

#include <string>

namespace ArpChat
{
void        print_mac_address( const unsigned char* mac_address );
std::string macToString( uint8_t* mac );
void        print_packet( const unsigned char* packet, int length );
}   // namespace ArpChat