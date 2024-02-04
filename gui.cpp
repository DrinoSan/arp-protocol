#include "gui.h"

namespace ArpChat
{

ArpGui::ArpGui()
{
    inputField =
        ftxui::Input( &inputBuffer, "Type a message and press Enter..." );
}

ftxui::Component ArpGui::getVInputField()
{
    return ftxui::Container::Vertical( {
        inputField,
    } );
}

void ArpGui::prepareInputFieldForChat()
{
    inputField =
        ftxui::Input( &inputBuffer, "Type a message and press Enter..." );
}

}   // namespace ArpChat
