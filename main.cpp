#include <cstring>
#include <iostream>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <thread>
#include <libnet.h>

// ArpChat includes
#include "messages.h"

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
    print_packet( packet, pkthdr->len );
    std::cout << "------------------------------------" << std::endl;
    if ( !ArpChat::EthernetFrame::isArp( packet ) )
    {
        // We are only interested in arp packages
        return;
    }

    // PLEN protocol address length which is in ipv4 = 4 because ip address is
    // 4 byte long We will use this to set our length of our message Also PLEN
    // sets the limit of our messages which is 1 byte or 255 characters

    // Our chat will use as a prefix identifier sand
    // And then followed by our message

    // SPA will be our message we want to send

    ArpChat::EthernetFrame frame( packet, pkthdr->caplen );
    std::cout << "Destination Mac: " << frame.destinationMacAddr << '\n';
    std::cout << "Source Mac:      " << frame.sourceMacAddr << '\n';

    std::cout << "ARP Frame Information:\n";
    std::cout << "Hardware Type: 0x" << std::hex << frame.payload.htype
              << std::dec << "\n";
    std::cout << "Ether type / Frame Type: 0x" << std::hex << frame.etherType
              << std::dec << "\n";
    std::cout << "Hardware Size: " << static_cast<int>( frame.payload.hlen )
              << "\n";
    std::cout << "Protocol Size: " << static_cast<int>( frame.payload.plen )
              << "\n";
    std::cout << "Operation Code: " << frame.payload.oper << "\n";

    std::cout << "Sender MAC Address: " << frame.payload.sha;
    // print_mac_address( arp_packet + SENDER_HARDWARE_ADDRESS );
    std::cout << "\n";

    std::cout << "\n";
}

void capturePackets()
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

    // Start capturing packets and pass them to the packet_handler function
    pcap_loop( handle, 0, packet_handler, nullptr );

    pcap_close( handle );
}

void sendGratuitousArp() {
    libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];

    // Initialize the library
    l = libnet_init(LIBNET_LINK, "en0", errbuf);
    if (l == nullptr) {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        return;
    }

    // Replace these with your actual MAC and IP addresses
    uint8_t sourceMac[] = {0x74, 0x8f, 0x3c, 0xb9, 0x8f, 0xf5};
    uint8_t sourceIp[] = {192, 168, 0, 99};
    uint8_t broadcastMac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    std::string customData = "HI THIS IS A TEST";
    // Build ARP packet
    libnet_ptag_t arp_tag = libnet_build_arp(
        ARPHRD_ETHER,
        ETHERTYPE_IP,
        6,
        customData.size(),
        ARPOP_REQUEST,
        sourceMac,
        reinterpret_cast<uint8_t*>(customData.data()),
        broadcastMac,
        reinterpret_cast<uint8_t*>(customData.data()),
        nullptr, 0,
        l, 0
    );

    if (arp_tag == -1) {
        std::cerr << "libnet_build_arp() failed: " << libnet_geterror(l) << std::endl;
        libnet_destroy(l);
        return;
    }

    // Build Ethernet frame
    libnet_ptag_t eth_tag = libnet_build_ethernet(
        broadcastMac,
        sourceMac,
        ETHERTYPE_ARP,
        nullptr, 0,
        l, 0
    );

    if (eth_tag == -1) {
        std::cerr << "libnet_build_ethernet() failed: " << libnet_geterror(l) << std::endl;
        libnet_destroy(l);
        return;
    }

    // Write the packet to the network
    int bytes_written = libnet_write(l);
    if (bytes_written == -1) {
        std::cerr << "libnet_write() failed: " << libnet_geterror(l) << std::endl;
    } else {
        std::cout << "Gratuitous ARP packet sent successfully." << std::endl;
    }

    // Cleanup
    libnet_destroy(l);
}

int main()
{
    // Start a thread for packet capture
    std::thread captureThread( capturePackets );

    // Sending packet
    sendGratuitousArp();

    // Wait for the capture thread to finish
    captureThread.join();

    return 0;
}
