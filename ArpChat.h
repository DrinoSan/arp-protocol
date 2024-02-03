#pragma once

#include <deque>
#include <mutex>
#include <string>

#include "gui.h"

namespace ArpChat
{
class ArpChat
{
  public:
    ArpChat()  = default;
    ~ArpChat() = default;

    // Function to add a new message to the chat history.
    void AddMessage( const std::string& message );

    // This function needs a refactoring because copy paste from above
    void announceNewUser();

    // Gui
    auto getVInputField();
    void setInputFieldText( const std::string& inputText );

    // Gui
  public:
    ArpGui arpGui;

  public:
    // Chat and history stuff
    std::mutex              chatMutex;
    std::deque<std::string> chatHistory;
    bool                    updateFlag = false;
};
}   // namespace ArpChat
