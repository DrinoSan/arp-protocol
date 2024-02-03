#include "ArpChat.h"

namespace ArpChat
{
void ArpChat::AddMessage( const std::string& message )
{
    std::lock_guard<std::mutex> lock( chatMutex );
    chatHistory.push_back( message );
    updateFlag = true;

    // Limit the chat history to a certain number of messages.
    const size_t maxHistorySize = 10;
    while ( chatHistory.size() > maxHistorySize )
    {
        chatHistory.pop_front();
    }

    // Dummy way for debugging
    if ( message.empty() == true )
    {
        exit( 1 );
    }
}

void ArpChat::announceNewUser() {}

void ArpChat::setInputFieldText( const std::string& inputText )
{
    arpGui.inputField = ftxui::Input( &arpGui.inputBuffer, inputText );
}

}   // namespace ArpChat
