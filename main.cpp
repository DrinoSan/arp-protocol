#include <iomanip>
#include <iostream>
#include <pcap.h>

// https://en.wikipedia.org/wiki/Address_Resolution_Protocol#cite_note-IANA-2
constexpr int32_t SENDER_HARDWARE_ADDRESS{ 8 };
constexpr int32_t SENDER_PROTOCOL_ADDRESS{ 14 };   // Ipv4

constexpr int32_t TARGET_HARDWARE_ADDRESS{ 18 };
constexpr int32_t TARGET_PROTOCOL_ADDRESS{ 24 };   // Ipv4

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
    const unsigned char* ethernet_header = packet;

    // Print the whole frame
    print_packet( packet, pkthdr->caplen );

    // Important: The physicall layer is alredy unpacking the frame form layer
    // 1, basically preamble and sfd is already cut off when we receive it here
    // Assuming EtherType is in big-endian format -> Networks use big-endian
    uint16_t ether_type =
        ( ethernet_header[ 12 ] << 8 ) | ethernet_header[ 13 ];

    // ARP EtherType
    if ( ether_type == 0x0806 )
    {
        const unsigned char* arp_packet =
            packet + 14;   // ARP packet starts at offset 14
                           // 6 Byte Source Mac address
                           // 6 Byte Destination Mac address
                           // 2 Byte EtherType

        // ARP header fields
        // https://en.wikipedia.org/wiki/Address_Resolution_Protocol#cite_note-IANA-2
        uint16_t hardware_type = ( arp_packet[ 0 ] << 8 ) | arp_packet[ 1 ];
        uint16_t protocol_type =
            ( arp_packet[ 2 ] << 8 ) |
            arp_packet[ 3 ];   // This is mostly ipv4 0x0800.
                               // It identifies the network layer protocol for
                               // which arp is resolving the address
        uint8_t hardware_size =
            arp_packet[ 4 ];   // Length of hardware length (Mac address)
        uint8_t protocol_size =
            arp_packet[ 5 ];   // Length of protocol network address ipv4 = 4
                               // byte example: 255.255.255.255
        uint16_t operation_code =
            ( arp_packet[ 6 ] << 8 ) |
            arp_packet[ 7 ];   // Specifies the operation that the sender is
                               // performing: 1 for request, 2 for reply.

        std::cout << "ARP Frame Information:\n";
        std::cout << "Hardware Type: 0x" << std::hex << hardware_type
                  << std::dec << "\n";
        std::cout << "Ether type / Frame Type: 0x" << std::hex << protocol_type
                  << std::dec << "\n";
        std::cout << "Hardware Size: " << static_cast<int>( hardware_size )
                  << "\n";
        std::cout << "Protocol Size: " << static_cast<int>( protocol_size )
                  << "\n";
        std::cout << "Operation Code: " << operation_code << "\n";

        std::cout << "Sender MAC Address: ";
        print_mac_address( arp_packet + SENDER_HARDWARE_ADDRESS );
        std::cout << "\n";

        std::cout << "Sender IP Address: ";
        for ( int i = 0; i < 4; ++i )
        {
            std::cout << static_cast<int>(
                arp_packet[ SENDER_PROTOCOL_ADDRESS + i ] );
            if ( i < 3 )
                std::cout << ".";
        }
        std::cout << "\n";

        std::cout << "Target MAC Address: ";
        print_mac_address( arp_packet + TARGET_HARDWARE_ADDRESS );
        std::cout << "\n";

        std::cout << "Target IP Address: ";
        for ( int i = 0; i < 4; ++i )
        {
            std::cout << static_cast<int>(
                arp_packet[ TARGET_PROTOCOL_ADDRESS + i ] );
            if ( i < 3 )
                std::cout << ".";
        }
        std::cout << "\n";
    }
}

int main()
{
    char errbuf[ PCAP_ERRBUF_SIZE ];

    // Open a network interface for packet capture
    pcap_t* handle = pcap_open_live( "en0", BUFSIZ, 1, 1000, errbuf );

    if ( handle == nullptr )
    {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        return -1;
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
        return -1;
    }

    if ( pcap_setfilter( handle, &fp ) == -1 )
    {
        std::cerr << "Couldn't install filter " << filter_exp << ": "
                  << pcap_geterr( handle ) << std::endl;
        return -1;
    }

    // Start capturing packets and pass them to the packet_handler function
    pcap_loop( handle, 0, packet_handler, nullptr );

    pcap_close( handle );
    return 0;
}
