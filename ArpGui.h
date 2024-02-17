#pragma once

// System Headers
#include <deque>
#include <map>
#include <string>

// Project Headers
#include "ArpProtocol.h"

// FTXUI stuff
#include "ftxui/component/component.hpp"
#include <ftxui/component/component_base.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/string.hpp>

namespace ArpChat
{
class ArpGui
{
  public:
    ArpGui();
    ~ArpGui() = default;

    inline auto getInputField() { return inputField; }

    // Clear inputBuffer
    inline void clearInputBuffer() { inputBuffer.clear(); }

    // Prepare for normal text mode in gui
    void prepareChatInputField()
    {
        inputField =
            ftxui::Input( &inputBuffer, "Type a message and press Enter..." );
    }

    void initRendererComponent( const std::deque<std::string>& chatHistory,
                                ArpProtocol&                   arpProtocol );

    void run( const std::deque<std::string>& chatHistory,
              ArpProtocol&                   arpProtocol );
    void postEvent( ftxui::Event event );

    std::string
    registerMyself( std::map<std::string, std::string>& macToUsernameMapping );

    ftxui::Component getVContainerInputField() const;

  private:
    std::string                      inputBuffer;
    ftxui::Component                 inputField;
    ftxui::ScreenInteractive         screen;
    ftxui::Component                 renderer;
    ftxui::Component                 component;
};
}   // namespace ArpChat
