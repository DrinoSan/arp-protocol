#pragma once

// System Headers
#include <deque>
#include <map>
#include <mutex>
#include <string>

// Project headers
#include "ArpGui.h"

namespace ArpChat
{
class ArpChat
{
  public:
    explicit ArpChat( std::string interface_tmp ) : arpProtocol{ interface_tmp }
    {
    }

    // Function to add a new message to the chat history.
    void AddMessage( const std::string& message );

    // This function needs a refactoring because copy paste from above
    void
    announceNewUser( std::map<std::string, std::string>& macToUsernameMapping );

    // Gui stuff
    inline void postGuiEvent( const ftxui::Event& event )
    {
        arpGui.postEvent( event );
    }

    inline void run() { arpGui.run( chatHistory, arpProtocol ); }

    inline const char* getInterface() const
    {
        return arpProtocol.getInterface().c_str();
    }

    void prepareGui();

  public:
    // Chat and history stuff
    std::mutex              chatMutex;
    std::deque<std::string> chatHistory;
    bool                    updateFlag = false;

  public:
    ArpProtocol arpProtocol;
    ArpGui      arpGui;
};
}   // namespace ArpChat
