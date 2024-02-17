#include "ArpGui.h"

namespace ArpChat
{

using namespace ftxui;
ArpGui::ArpGui() : screen{ ftxui::ScreenInteractive::TerminalOutput() }
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

// TODO FÜR MORGEN
// chatMutex und ChatHistory solltn eher member für die gui sein da sie nur zum
// Anzeigen da sind
void ArpGui::createRenderer( std::mutex&              chatMutex,
                             std::deque<std::string>& chatHistory )
{
    renderer = Renderer(
        getVInputField(),
        [ & ]
        {
            std::lock_guard<std::mutex> lock( this->chatMutex );

            std::vector<Element> chatElements;
            for ( const auto& message : this->chatHistory )
            {
                chatElements.push_back( text( message ) );
            }

            // Combine the text elements into a vbox.
            auto tmpVbox = vbox( std::move( chatElements ) );

            // Reset the update flag.
            this->updateFlag = false;

            // Create a vbox for the chat history and input field.
            auto vboxWithInput =
                vbox( { text( L"Chat History" ) | hcenter, tmpVbox, separator(),
                        hbox( text( " Message Input : " ),
                              getInputField()->Render() ) } ) |
                border;

            return vboxWithInput;
        } );
}

void ArpGui::createComponent()
{
    component =
        CatchEvent( renderer,
                    [ & ]( Event event )
                    {
                        if ( event == ftxui::Event::Character( 'q' ) )
                        {
                            arpChat.arpGui.screen.ExitLoopClosure()();
                            stopCapturing = false;
                            return true;
                        }
                        else if ( event == ftxui::Event::Return )
                        {
                            // Call your function to send messages.
                            arpChat.sendGratuitousArp( arpChat.arpGui.screen );
                            return true;
                        }
                        return false;
                    } );
}

}   // namespace ArpChat
