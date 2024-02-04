#pragma once

#include <deque>
#include <map>
#include <mutex>
#include <string>

#include "gui.h"

namespace ArpChat
{
class ArpChat
{
  public:
    explicit ArpChat( std::string interface_tmp ) : interface{ interface_tmp }
    {
        printf( "Created arpChat for interface: %s\n", interface.c_str() );
    }
    ~ArpChat() = default;

    // Function to add a new message to the chat history.
    void AddMessage( const std::string& message );

    // This function needs a refactoring because copy paste from above
    void
    announceNewUser( std::map<std::string, std::string> macToUsernameMapping );

    void sendGratuitousArp( ftxui::ScreenInteractive& screen,
                            bool                      announceNewUser = false );

    // Gui
    void setInputFieldText( const std::string& inputText );

    // Gui
  public:
    ArpGui arpGui;

  public:
    // Chat and history stuff
    std::mutex              chatMutex;
    std::deque<std::string> chatHistory;
    bool                    updateFlag = false;

  public:
    std::string interface;
};
}   // namespace ArpChat
