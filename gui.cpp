#include "ftxui/component/component.hpp"

#include "gui.h"


namespace ArpChat
{

  ArpGui::ArpGui()
  {
    inputField = ftxui::Input( &inputBuffer, "Type a message and press Enter..." );
  }

  ftxui::Component ArpGui::getVInputField()
    {
        return ftxui::Container::Vertical( {
            inputField,
        } );
    }
}



