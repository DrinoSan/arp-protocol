#include <cstdint>
#include <iomanip>
#include <string>
#include <sys/_types/_int16_t.h>

namespace ArpChat
{
class ArpPackage
{
  public:
    ArpPackage()  = default;
    ~ArpPackage() = default;

    int16_t     htype;   // Hardware Type
    int16_t     ptype;   // Protocol Type
    int16_t     hlen;    // Hardware address length
    int16_t     plen;    // Protocol length
    int16_t     oper;    // Operation
    std::string sha;     // Sender Hardware address
    std::string spa;     // Sender Protocol address
    std::string tha;     // Target Hardware address
    std::string tpa;     // Target protocol address
};

class EthernetFrame
{
  public:
    EthernetFrame( const unsigned char* packet, int length );
    ~EthernetFrame() = default;

    std::string destinationMacAddr;
    std::string sourceMacAddr;
    int16_t     etherType;

    // Payload in our case ArpPackage
    ArpPackage payload;

    static bool isArp( const unsigned char* packet );
    bool        parseEthernetFrame( const unsigned char* packet, int length );
    std::string hexToString( const unsigned char* packet );
    std::string ipToString( const unsigned char* packet );
    void        printMacAddress( bool showDestination ) const;
};

}   // namespace ArpChat
