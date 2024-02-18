#include <libnet.h>
#include <memory>
#include <mutex>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <string>

#include "ArpChat.h"
#include "messages.h"
#include "utils.h"

namespace ArpChat
{

constexpr size_t maxHistorySize{ 10 };

//-----------------------------------------------------------------------------
void ArpChat::AddMessage( const std::string& message )
{
    std::lock_guard<std::mutex> lock( arpProtocol.chatMutex );
    chatHistory.push_back( message );
    updateFlag = true;

    // Limit the chat history to a certain number of messages.
    while ( chatHistory.size() > maxHistorySize )
    {
        chatHistory.pop_front();
    }
}

//-----------------------------------------------------------------------------
void ArpChat::announceNewUser(
    std::map<std::string, std::string>& macToUsernameMapping )
{
    std::string myUserName = arpGui.registerMyself( macToUsernameMapping );
    arpProtocol.sendArpMessage( myUserName,
                                std::string( NEW_USER_ANNOUNCEMENT ) );

    // Preparing inputField for normal chat
    arpGui.clearInputBuffer();
    arpGui.prepareChatInputField();
}

//-----------------------------------------------------------------------------
void ArpChat::prepareGui()
{
    arpGui.initRendererComponent( chatHistory, arpProtocol );
}

}   // namespace ArpChat
