# Arp
Learning about arp protocol and some network stuff

## General
In general this little project is working and does what it should do.
We can communicate with other users via the arp protocol.

## Messages
The messages file contains all the layer data (EthernetFrame and Arp payload)

Currently the EthernetFrame class is responsible to parse the raw bytes into a EthernetFrame and its Arp payload, this is at the moment done in the constructor but it seems it must be moved.

- The MAC and IP addresses are saved as a std::string with the functions hexToString and ipToString.
- The function isArp is a static function to check if it is the correct etherType because we only want to interact with Arp types.
- The class EthernetFrame has a variable called payload which is the ArpPackage data (Fields taken from [Wikipedia](https://en.wikipedia.org/wiki/Address_Resolution_Protocol#cite_note-IANA-2))
- The EthernetFrame fields are from [Wikipedia](https://en.wikipedia.org/wiki/Ethernet_frame)


## Sending Arp over the Network
For this we use the library [libnet](https://github.com/libnet/libnet)
To identify a ArpChat message we add a prefix which is "SAND" to each message.


## Current Status
Working on refactoring.
- Currently there is kinda a split going on to split responsibility between arpChat and arpGui
 - Still need to split them in a better way and cleaner much cleaner
 - In main there is some code which must be moved to arpGui / arpChat
- Moved Several functions from main to ArpChat class

## Added 
- Parsing of simple command line arguments.
 - Previously in the code the network interface was hardcoded, now the user can provide it himself. If the interface can not be read we will show a list of all available network interfaces


## Missing
- Automagically get Mac address of computer



## More
[Blog](https://project-folio.eu/articles/cpp-abuse-arp)
