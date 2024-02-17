#include <libnet.h>
#include <memory>
#include <mutex>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <string>

#include "messages.h"
#include "utils.h"


namespace ArpChat
{
class ArpProtocol
{
   public:
   ArpProtocol( std::string& interface_ ) : interface{ interface_ }
   {
        printf( "Created arpChat for interface: %s\n", interface.c_str() );
   }
   ~ArpProtocol() = default;

   public:
   // Sending of gratuitous arp message 
   bool sendArpMessage(  const std::string& inputBuffer, const std::string& MESSAGE_PREFIX_TYPE );

   inline const std::string& getInterface() const { return interface; }

   private:
      std::string interface;

   public:
      std::mutex  chatMutex;
};
};
